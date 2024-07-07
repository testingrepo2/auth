package api

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/aaronarduino/goqrsvg"
	svg "github.com/ajstarks/svgo"
	"github.com/boombuler/barcode/qr"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/gofrs/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/supabase/auth/internal/crypto"
	"github.com/supabase/auth/internal/hooks"
	"github.com/supabase/auth/internal/metering"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
	"github.com/supabase/auth/internal/utilities"
)

const DefaultQRSize = 3

type EnrollFactorParams struct {
	FriendlyName string `json:"friendly_name"`
	FactorType   string `json:"factor_type"`
	Issuer       string `json:"issuer"`
}

type TOTPObject struct {
	QRCode string `json:"qr_code"`
	Secret string `json:"secret"`
	URI    string `json:"uri"`
}

type EnrollFactorResponse struct {
	ID           uuid.UUID  `json:"id"`
	Type         string     `json:"type"`
	FriendlyName string     `json:"friendly_name"`
	TOTP         TOTPObject `json:"totp,omitempty"`
}

type WebauthnRegisterStartResponse struct {
	PublicKeyCredentialRequestOptions *protocol.CredentialCreation `json:"public_key_credential_request_options"`
	FactorID                          uuid.UUID                    `json:"factor_id"`
}

type VerifyFactorParams struct {
	ChallengeID uuid.UUID `json:"challenge_id"`
	Code        string    `json:"code"`
}

type ChallengeFactorResponse struct {
	ID        uuid.UUID `json:"id"`
	ExpiresAt int64     `json:"expires_at"`
}

type WebauthnLoginStartResponse struct {
	PublicKeyCredentialRequestOptions *protocol.CredentialAssertion `json:"public_key_credential_request_options"`
	// TBD
}

type UnenrollFactorResponse struct {
	ID uuid.UUID `json:"id"`
}

const (
	InvalidFactorOwnerErrorMessage = "Factor does not belong to user"
	QRCodeGenerationErrorMessage   = "Error generating QR Code"
)

func (a *API) handleWebauthnEnrollment(w http.ResponseWriter, r *http.Request, params *EnrollFactorParams) error {
	// TODO: re-use stuff
	// TODO: Check for unique friendly name
	ctx := r.Context()
	user := getUser(ctx)
	config := a.config
	db := a.db.WithContext(ctx)
	ipAddress := utilities.GetIPAddress(r)

	webAuthn := config.MFA.Webauthn.Webauthn
	// TODO: Figure out what to do with session data
	options, session, err := webAuthn.BeginRegistration(user)
	if err != nil {
		// TODO: return a proper error
		return internalServerError("internal server error")
	}
	ws := &models.WebauthnSession{
		SessionData: session,
	}
	factor := models.NewFactor(user, params.FriendlyName, models.Webauthn, models.FactorStateUnverified)
	challenge := ws.ToChallenge(factor.ID, ipAddress)
	err = db.Transaction(func(tx *storage.Connection) error {
		if terr := tx.Create(factor); err != nil {
			return terr
		}
		if terr := tx.Create(challenge); terr != nil {
			return terr
		}
		return nil

	})
	if err != nil {
		return err
	}

	return sendJSON(w, http.StatusOK, &WebauthnRegisterStartResponse{
		PublicKeyCredentialRequestOptions: options,
		FactorID:                          factor.ID,
		// TODO: move the challenge creation logic to "Challenge"
	})

}

func (a *API) handleWebauthnVerification(w http.ResponseWriter, r *http.Request, params *VerifyFactorParams) error {
	// TODO: don't reuse this
	ctx := r.Context()
	user := getUser(ctx)
	config := a.config
	factor := getFactor(ctx)
	webAuthn := config.MFA.Webauthn.Webauthn
	// db := a.db.WithContext(ctx)
	challenge, err := models.FindChallengeByID(a.db, params.ChallengeID)
	if err != nil {
		return err
	}
	sessionData := challenge.ToSession(user.ID, config.MFA.ChallengeExpiryDuration)

	// TODO: Decide based on the factor state whether this is a registration or login
	if factor.Status == models.FactorStateUnverified.String() {
		_, err := webAuthn.FinishRegistration(user, sessionData, r)
		if err != nil {
			return err
		}
		// TODO: Do verify the credential
		return badRequestError(ErrorCodeValidationFailed, "registration here")
	}

	// Login case where factor is verified
	_, err = webAuthn.FinishLogin(user, sessionData, r)
	if err != nil {
		return internalServerError("login borked")
	}

	return badRequestError(ErrorCodeValidationFailed, "unknown error")
}

func (a *API) EnrollFactor(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	user := getUser(ctx)
	session := getSession(ctx)
	config := a.config
	db := a.db.WithContext(ctx)

	if session == nil || user == nil {
		return internalServerError("A valid session and a registered user are required to enroll a factor")
	}

	params := &EnrollFactorParams{}
	if err := retrieveRequestParams(r, params); err != nil {
		return err
	}
	switch params.FactorType {
	case models.Webauthn:
		return a.handleWebauthnEnrollment(w, r, params)
	case models.TOTP:
	// No return statement, continue execution with the rest of the function

	default:
		return badRequestError(ErrorCodeValidationFailed, "factor_type needs to be totp or webauthn")
	}

	issuer := ""
	if params.Issuer == "" {
		u, err := url.ParseRequestURI(config.SiteURL)
		if err != nil {
			return internalServerError("site url is improperly formatted")
		}
		issuer = u.Host
	} else {
		issuer = params.Issuer
	}

	factors := user.Factors

	factorCount := len(factors)
	numVerifiedFactors := 0
	if err := models.DeleteExpiredFactors(db, config.MFA.FactorExpiryDuration); err != nil {
		return err
	}

	for _, factor := range factors {
		if factor.IsVerified() {
			numVerifiedFactors += 1
		}
	}

	if factorCount >= int(config.MFA.MaxEnrolledFactors) {
		return forbiddenError(ErrorCodeTooManyEnrolledMFAFactors, "Maximum number of verified factors reached, unenroll to continue")
	}

	if numVerifiedFactors >= config.MFA.MaxVerifiedFactors {
		return forbiddenError(ErrorCodeTooManyEnrolledMFAFactors, "Maximum number of verified factors reached, unenroll to continue")
	}

	if numVerifiedFactors > 0 && !session.IsAAL2() {
		return forbiddenError(ErrorCodeInsufficientAAL, "AAL2 required to enroll a new factor")
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: user.GetEmail(),
	})
	if err != nil {
		return internalServerError(QRCodeGenerationErrorMessage).WithInternalError(err)
	}

	var buf bytes.Buffer
	svgData := svg.New(&buf)
	qrCode, _ := qr.Encode(key.String(), qr.H, qr.Auto)
	qs := goqrsvg.NewQrSVG(qrCode, DefaultQRSize)
	qs.StartQrSVG(svgData)
	if err = qs.WriteQrSVG(svgData); err != nil {
		return internalServerError(QRCodeGenerationErrorMessage).WithInternalError(err)
	}
	svgData.End()

	factor := models.NewFactor(user, params.FriendlyName, params.FactorType, models.FactorStateUnverified)
	if err := factor.SetSecret(key.Secret(), config.Security.DBEncryption.Encrypt, config.Security.DBEncryption.EncryptionKeyID, config.Security.DBEncryption.EncryptionKey); err != nil {
		return err
	}

	err = db.Transaction(func(tx *storage.Connection) error {
		if terr := tx.Create(factor); terr != nil {
			pgErr := utilities.NewPostgresError(terr)
			if pgErr.IsUniqueConstraintViolated() {
				return unprocessableEntityError(ErrorCodeMFAFactorNameConflict, fmt.Sprintf("A factor with the friendly name %q for this user likely already exists", factor.FriendlyName))
			}
			return terr

		}
		if terr := models.NewAuditLogEntry(r, tx, user, models.EnrollFactorAction, r.RemoteAddr, map[string]interface{}{
			"factor_id": factor.ID,
		}); terr != nil {
			return terr
		}
		return nil
	})
	if err != nil {
		return err
	}

	return sendJSON(w, http.StatusOK, &EnrollFactorResponse{
		ID:           factor.ID,
		Type:         models.TOTP,
		FriendlyName: factor.FriendlyName,
		TOTP: TOTPObject{
			// See: https://css-tricks.com/probably-dont-base64-svg/
			QRCode: buf.String(),
			Secret: key.Secret(),
			URI:    key.URL(),
		},
	})
}

func (a *API) ChallengeFactor(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	config := a.config
	db := a.db.WithContext(ctx)

	user := getUser(ctx)
	factor := getFactor(ctx)
	ipAddress := utilities.GetIPAddress(r)
	// TODO: Check if webauthn factor, do separate branch for login
	var challenge *models.Challenge
	if factor.FactorType == models.Webauthn {
		// Maybe vary behaviour based on whether it is registration or login flow
		webAuthn := a.config.MFA.Webauthn.Webauthn
		// if factor is not verified or it is not a webauthn factor then return
		options, session, err := webAuthn.BeginLogin(user)
		if err != nil {
			return err
		}
		ws := &models.WebauthnSession{
			SessionData: session,
		}
		challenge = ws.ToChallenge(factor.ID, ipAddress)

		return sendJSON(w, http.StatusOK, &WebauthnLoginStartResponse{
			PublicKeyCredentialRequestOptions: options,
		})
	} else {
		challenge = models.NewChallenge(factor, ipAddress)
	}

	if err := db.Transaction(func(tx *storage.Connection) error {
		if terr := tx.Create(challenge); terr != nil {
			return terr
		}
		if terr := models.NewAuditLogEntry(r, tx, user, models.CreateChallengeAction, r.RemoteAddr, map[string]interface{}{
			"factor_id":     factor.ID,
			"factor_status": factor.Status,
		}); terr != nil {
			return terr
		}
		return nil
	}); err != nil {
		return err
	}

	return sendJSON(w, http.StatusOK, &ChallengeFactorResponse{
		ID:        challenge.ID,
		ExpiresAt: challenge.GetExpiryTime(config.MFA.ChallengeExpiryDuration).Unix(),
	})
}

func (a *API) VerifyFactor(w http.ResponseWriter, r *http.Request) error {
	var err error
	ctx := r.Context()
	user := getUser(ctx)
	factor := getFactor(ctx)
	config := a.config
	db := a.db.WithContext(ctx)

	params := &VerifyFactorParams{}
	if err := retrieveRequestParams(r, params); err != nil {
		return err
	}
	currentIP := utilities.GetIPAddress(r)

	if !factor.IsOwnedBy(user) {
		return internalServerError(InvalidFactorOwnerErrorMessage)
	}
	// Branch off for webauthn type factors.
	if factor.FactorType == models.Webauthn {
		return a.handleWebauthnVerification(w, r, params)
	}

	challenge, err := models.FindChallengeByID(db, params.ChallengeID)
	if err != nil && models.IsNotFoundError(err) {
		return notFoundError(ErrorCodeMFAFactorNotFound, "MFA factor with the provided challenge ID not found")
	} else if err != nil {
		return internalServerError("Database error finding Challenge").WithInternalError(err)
	}

	if challenge.VerifiedAt != nil || challenge.IPAddress != currentIP {
		return unprocessableEntityError(ErrorCodeMFAIPAddressMismatch, "Challenge and verify IP addresses mismatch")
	}

	if challenge.HasExpired(config.MFA.ChallengeExpiryDuration) {
		if err := db.Destroy(challenge); err != nil {
			return internalServerError("Database error deleting challenge").WithInternalError(err)
		}
		return unprocessableEntityError(ErrorCodeMFAChallengeExpired, "MFA challenge %v has expired, verify against another challenge or create a new challenge.", challenge.ID)
	}

	secret, shouldReEncrypt, err := factor.GetSecret(config.Security.DBEncryption.DecryptionKeys, config.Security.DBEncryption.Encrypt, config.Security.DBEncryption.EncryptionKeyID)
	if err != nil {
		return internalServerError("Database error verifying MFA TOTP secret").WithInternalError(err)
	}

	valid, verr := totp.ValidateCustom(params.Code, secret, time.Now().UTC(), totp.ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})

	if config.Hook.MFAVerificationAttempt.Enabled {
		input := hooks.MFAVerificationAttemptInput{
			UserID:   user.ID,
			FactorID: factor.ID,
			Valid:    valid,
		}

		output := hooks.MFAVerificationAttemptOutput{}
		err := a.invokeHook(nil, r, &input, &output, a.config.Hook.MFAVerificationAttempt.URI)
		if err != nil {
			return err
		}

		if output.Decision == hooks.HookRejection {
			if err := models.Logout(db, user.ID); err != nil {
				return err
			}

			if output.Message == "" {
				output.Message = hooks.DefaultMFAHookRejectionMessage
			}

			return forbiddenError(ErrorCodeMFAVerificationRejected, output.Message)
		}
	}

	if !valid {
		if shouldReEncrypt && config.Security.DBEncryption.Encrypt {
			if err := factor.SetSecret(secret, true, config.Security.DBEncryption.EncryptionKeyID, config.Security.DBEncryption.EncryptionKey); err != nil {
				return err
			}

			if err := db.UpdateOnly(factor, "secret"); err != nil {
				return err
			}
		}
		return unprocessableEntityError(ErrorCodeMFAVerificationFailed, "Invalid TOTP code entered").WithInternalError(verr)
	}

	var token *AccessTokenResponse
	err = db.Transaction(func(tx *storage.Connection) error {
		var terr error
		if terr = models.NewAuditLogEntry(r, tx, user, models.VerifyFactorAction, r.RemoteAddr, map[string]interface{}{
			"factor_id":    factor.ID,
			"challenge_id": challenge.ID,
		}); terr != nil {
			return terr
		}
		if terr = challenge.Verify(tx); terr != nil {
			return terr
		}
		if !factor.IsVerified() {
			if terr = factor.UpdateStatus(tx, models.FactorStateVerified); terr != nil {
				return terr
			}
		}
		if shouldReEncrypt && config.Security.DBEncryption.Encrypt {
			es, terr := crypto.NewEncryptedString(factor.ID.String(), []byte(secret), config.Security.DBEncryption.EncryptionKeyID, config.Security.DBEncryption.EncryptionKey)
			if terr != nil {
				return terr
			}

			factor.Secret = es.String()
			if terr := tx.UpdateOnly(factor, "secret"); terr != nil {
				return terr
			}
		}
		user, terr = models.FindUserByID(tx, user.ID)
		if terr != nil {
			return terr
		}
		token, terr = a.updateMFASessionAndClaims(r, tx, user, models.TOTPSignIn, models.GrantParams{
			FactorID: &factor.ID,
		})
		if terr != nil {
			return terr
		}
		if terr = a.setCookieTokens(config, token, false, w); terr != nil {
			return internalServerError("Failed to set JWT cookie. %s", terr)
		}
		if terr = models.InvalidateSessionsWithAALLessThan(tx, user.ID, models.AAL2.String()); terr != nil {
			return internalServerError("Failed to update sessions. %s", terr)
		}
		if terr = models.DeleteUnverifiedFactors(tx, user); terr != nil {
			return internalServerError("Error removing unverified factors. %s", terr)
		}
		return nil
	})
	if err != nil {
		return err
	}
	metering.RecordLogin(string(models.MFACodeLoginAction), user.ID)

	return sendJSON(w, http.StatusOK, token)

}

func (a *API) UnenrollFactor(w http.ResponseWriter, r *http.Request) error {
	var err error
	ctx := r.Context()
	user := getUser(ctx)
	factor := getFactor(ctx)
	session := getSession(ctx)
	db := a.db.WithContext(ctx)

	if factor == nil || session == nil || user == nil {
		return internalServerError("A valid session and factor are required to unenroll a factor")
	}

	if factor.IsVerified() && !session.IsAAL2() {
		return unprocessableEntityError(ErrorCodeInsufficientAAL, "AAL2 required to unenroll verified factor")
	}
	if !factor.IsOwnedBy(user) {
		return internalServerError(InvalidFactorOwnerErrorMessage)
	}

	err = db.Transaction(func(tx *storage.Connection) error {
		var terr error
		if terr := tx.Destroy(factor); terr != nil {
			return terr
		}
		if terr = models.NewAuditLogEntry(r, tx, user, models.UnenrollFactorAction, r.RemoteAddr, map[string]interface{}{
			"factor_id":     factor.ID,
			"factor_status": factor.Status,
			"session_id":    session.ID,
		}); terr != nil {
			return terr
		}
		if terr = factor.DowngradeSessionsToAAL1(tx); terr != nil {
			return terr
		}
		return nil
	})
	if err != nil {
		return err
	}

	return sendJSON(w, http.StatusOK, &UnenrollFactorResponse{
		ID: factor.ID,
	})
}
