using System;
using Keycloak.Net.Models.AuthenticationManagement;
using Keycloak.Net.Models.Clients;
using Keycloak.Net.Models.ClientScopes;
using Keycloak.Net.Models.Groups;
using Keycloak.Net.Models.IdentityProviders;
using Keycloak.Net.Models.Organizations;
using Keycloak.Net.Models.ProtocolMappers;
using Keycloak.Net.Models.Roles;
using Keycloak.Net.Models.Users;

namespace Keycloak.Net.Models.RealmsAdmin;

public class Realm
{
    [JsonPropertyName("id")]
    public string Id { get; set; }

	[JsonPropertyName("realm")]
	// ReSharper disable once InconsistentNaming
    public string _Realm { get; set; }

    [JsonPropertyName("displayName")]
    public string? DisplayName { get; set; }

    [JsonPropertyName("displayNameHtml")]
    public string? DisplayNameHtml { get; set; }

    [JsonPropertyName("notBefore")]
    public int? NotBefore { get; set; }

    [JsonPropertyName("defaultSignatureAlgorithm")]
    public string DefaultSignatureAlgorithm { get; set; }

    [JsonPropertyName("revokeRefreshToken")]
    public bool? RevokeRefreshToken { get; set; }

    [JsonPropertyName("refreshTokenMaxReuse")]
    public int? RefreshTokenMaxReuse { get; set; }

    [JsonPropertyName("accessTokenLifespan")]
    public int? AccessTokenLifespan { get; set; }

    [JsonPropertyName("accessTokenLifespanForImplicitFlow")]
    public int? AccessTokenLifespanForImplicitFlow { get; set; }

    [JsonPropertyName("ssoSessionIdleTimeout")]
    public int? SsoSessionIdleTimeout { get; set; }

    [JsonPropertyName("ssoSessionMaxLifespan")]
    public int? SsoSessionMaxLifespan { get; set; }

    [JsonPropertyName("ssoSessionIdleTimeoutRememberMe")]
    public int? SsoSessionIdleTimeoutRememberMe { get; set; }

    [JsonPropertyName("ssoSessionMaxLifespanRememberMe")]
    public int? SsoSessionMaxLifespanRememberMe { get; set; }

    [JsonPropertyName("offlineSessionIdleTimeout")]
    public int? OfflineSessionIdleTimeout { get; set; }

    [JsonPropertyName("offlineSessionMaxLifespanEnabled")]
    public bool? OfflineSessionMaxLifespanEnabled { get; set; }

    [JsonPropertyName("offlineSessionMaxLifespan")]
    public int? OfflineSessionMaxLifespan { get; set; }

    [JsonPropertyName("clientSessionIdleTimeout")]
    public int? ClientSessionIdleTimeout { get; set; }

    [JsonPropertyName("clientSessionMaxLifespan")]
    public int? ClientSessionMaxLifespan { get; set; }

    [JsonPropertyName("clientOfflineSessionIdleTimeout")]
    public int? ClientOfflineSessionIdleTimeout { get; set; }

    [JsonPropertyName("clientOfflineSessionMaxLifespan")]
    public int? ClientOfflineSessionMaxLifespan { get; set; }

    [JsonPropertyName("accessCodeLifespan")]
    public int? AccessCodeLifespan { get; set; }

    [JsonPropertyName("accessCodeLifespanUserAction")]
    public int? AccessCodeLifespanUserAction { get; set; }

    [JsonPropertyName("accessCodeLifespanLogin")]
    public int? AccessCodeLifespanLogin { get; set; }

    [JsonPropertyName("actionTokenGeneratedByAdminLifespan")]
    public int? ActionTokenGeneratedByAdminLifespan { get; set; }

    [JsonPropertyName("actionTokenGeneratedByUserLifespan")]
    public int? ActionTokenGeneratedByUserLifespan { get; set; }

    [JsonPropertyName("oauth2DeviceCodeLifespan")]
    public int? Oauth2DeviceCodeLifespan { get; set; }

    [JsonPropertyName("oauth2DevicePollingInterval")]
    public int? Oauth2DevicePollingInterval { get; set; }

    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    [JsonPropertyName("sslRequired")]
    public string SslRequired { get; set; }

    [Obsolete (message: "Marked as 'deprecated' in Keycloak OpenAPI spec")]
    [JsonPropertyName("passwordCredentialGrantAllowed")]
    public bool? PasswordCredentialGrantAllowed { get; set; }

    [JsonPropertyName("registrationAllowed")]
    public bool? RegistrationAllowed { get; set; }

    [JsonPropertyName("registrationEmailAsUsername")]
    public bool? RegistrationEmailAsUsername { get; set; }

    [JsonPropertyName("rememberMe")]
    public bool? RememberMe { get; set; }

    [JsonPropertyName("verifyEmail")]
    public bool? VerifyEmail { get; set; }

    [JsonPropertyName("loginWithEmailAllowed")]
    public bool? LoginWithEmailAllowed { get; set; }

    [JsonPropertyName("duplicateEmailsAllowed")]
    public bool? DuplicateEmailsAllowed { get; set; }

    [JsonPropertyName("resetPasswordAllowed")]
    public bool? ResetPasswordAllowed { get; set; }

    [JsonPropertyName("editUsernameAllowed")]
    public bool? EditUsernameAllowed { get; set; }

    [Obsolete (message: "Marked as 'deprecated' in Keycloak OpenAPI spec")]
    [JsonPropertyName("userCacheEnabled")]
    public bool? UserCacheEnabled { get; set; }

    [Obsolete (message: "Marked as 'deprecated' in Keycloak OpenAPI spec")]
    [JsonPropertyName("realmCacheEnabled")]
    public bool? RealmCacheEnabled { get; set; }

    [JsonPropertyName("bruteForceProtected")]
    public bool? BruteForceProtected { get; set; }

    [JsonPropertyName("permanentLockout")]
    public bool? PermanentLockout { get; set; }

    [JsonPropertyName("maxTemporaryLockouts")]
    public int? MaxTemporaryLockouts { get; set; }

    [JsonPropertyName("maxFailureWaitSeconds")]
    public int? MaxFailureWaitSeconds { get; set; }

    [JsonPropertyName("minimumQuickLoginWaitSeconds")]
    public int? MinimumQuickLoginWaitSeconds { get; set; }

    [JsonPropertyName("waitIncrementSeconds")]
    public int? WaitIncrementSeconds { get; set; }

    [JsonPropertyName("quickLoginCheckMilliSeconds")]
    public long? QuickLoginCheckMilliSeconds { get; set; }

    [JsonPropertyName("maxDeltaTimeSeconds")]
    public int? MaxDeltaTimeSeconds { get; set; }

    [JsonPropertyName("failureFactor")]
    public int? FailureFactor { get; set; }

    [Obsolete (message: "Marked as 'deprecated' in Keycloak OpenAPI spec")]
    [JsonPropertyName("privateKey")]
    public string PrivateKey { get; set; }

    [Obsolete (message: "Marked as 'deprecated' in Keycloak OpenAPI spec")]
    [JsonPropertyName("publicKey")]
    public string PublicKey { get; set; }

    [Obsolete (message: "Marked as 'deprecated' in Keycloak OpenAPI spec")]
    [JsonPropertyName("certificate")]
    public string Certificate { get; set; }

    [Obsolete (message: "Marked as 'deprecated' in Keycloak OpenAPI spec")]
    [JsonPropertyName("codeSecret")]
    public string CodeSecret { get; set; }

    [JsonPropertyName("roles")]
    public Roles Roles { get; set; }

    [JsonPropertyName("groups")]
    public IEnumerable<Group> Groups { get; set; }

    [Obsolete (message: "Marked as 'deprecated' in Keycloak OpenAPI spec")]
    [JsonPropertyName("defaultRoles")]
    public IEnumerable<string>? DefaultRoles { get; set; }

    [JsonPropertyName("defaultRole")]
    public Role? DefaultRole { get; set; }

    [JsonPropertyName("adminPermissionsClient")]
    public Client AdminPermissionsClient { get; set; }

    [JsonPropertyName("defaultGroups")]
    public IEnumerable<string> DefaultGroups { get; set; }

    [Obsolete (message: "Marked as 'deprecated' in Keycloak OpenAPI spec")]
    [JsonPropertyName("requiredCredentials")]
    public IEnumerable<string> RequiredCredentials { get; set; }

    [JsonPropertyName("passwordPolicy")]
    public string PasswordPolicy { get; set; }

    [JsonPropertyName("otpPolicyType")]
    public string OtpPolicyType { get; set; }

    [JsonPropertyName("otpPolicyAlgorithm")]
    public string OtpPolicyAlgorithm { get; set; }

    [JsonPropertyName("otpPolicyInitialCounter")]
    public int? OtpPolicyInitialCounter { get; set; }

    [JsonPropertyName("otpPolicyDigits")]
    public int? OtpPolicyDigits { get; set; }

    [JsonPropertyName("otpPolicyLookAheadWindow")]
    public int? OtpPolicyLookAheadWindow { get; set; }

    [JsonPropertyName("otpPolicyPeriod")]
    public int? OtpPolicyPeriod { get; set; }

    [JsonPropertyName("otpPolicyCodeReusable")]
    public bool? OtpPolicyCodeReusable { get; set; }

    [JsonPropertyName("otpSupportedApplications")]
    public IEnumerable<string> OtpSupportedApplications { get; set; }

    [JsonPropertyName("localizationTexts")]
    public Dictionary<string, Dictionary<string, string>> LocalizationTexts { get; set; }

    [JsonPropertyName("webAuthnPolicyRpEntityName")]
    public string WebAuthnPolicyRpEntityName { get; set; }

    [JsonPropertyName("webAuthnPolicySignatureAlgorithms")]
    public IEnumerable<string> WebAuthnPolicySignatureAlgorithms { get; set; }

    [JsonPropertyName("webAuthnPolicyRpId")]
    public string WebAuthnPolicyRpId { get; set; }

    [JsonPropertyName("webAuthnPolicyAttestationConveyancePreference")]
    public string WebAuthnPolicyAttestationConveyancePreference { get; set; }

    [JsonPropertyName("webAuthnPolicyAuthenticatorAttachment")]
    public string WebAuthnPolicyAuthenticatorAttachment { get; set; }

    [JsonPropertyName("webAuthnPolicyRequireResidentKey")]
    public string WebAuthnPolicyRequireResidentKey { get; set; }

    [JsonPropertyName("webAuthnPolicyUserVerificationRequirement")]
    public string WebAuthnPolicyUserVerificationRequirement { get; set; }

    [JsonPropertyName("webAuthnPolicyCreateTimeout")]
    public int? WebAuthnPolicyCreateTimeout { get; set; }

    [JsonPropertyName("webAuthnPolicyAvoidSameAuthenticatorRegister")]
    public bool? WebAuthnPolicyAvoidSameAuthenticatorRegister { get; set; }

    [JsonPropertyName("webAuthnPolicyAcceptableAaguids")]
    public IEnumerable<string> WebAuthnPolicyAcceptableAaguids { get; set; }

    [JsonPropertyName("webAuthnPolicyExtraOrigins")]
    public IEnumerable<string> WebAuthnPolicyExtraOrigins { get; set; }

    [JsonPropertyName("webAuthnPolicyPasswordlessRpEntityName")]
    public string WebAuthnPolicyPasswordlessRpEntityName { get; set; }

    [JsonPropertyName("webAuthnPolicyPasswordlessSignatureAlgorithms")]
    public IEnumerable<string> WebAuthnPolicyPasswordlessSignatureAlgorithms { get; set; }

    [JsonPropertyName("webAuthnPolicyPasswordlessRpId")]
    public string WebAuthnPolicyPasswordlessRpId { get; set; }

    [JsonPropertyName("webAuthnPolicyPasswordlessAttestationConveyancePreference")]
    public string WebAuthnPolicyPasswordlessAttestationConveyancePreference { get; set; }

    [JsonPropertyName("webAuthnPolicyPasswordlessAuthenticatorAttachment")]
    public string WebAuthnPolicyPasswordlessAuthenticatorAttachment { get; set; }

    [JsonPropertyName("webAuthnPolicyPasswordlessRequireResidentKey")]
    public string WebAuthnPolicyPasswordlessRequireResidentKey { get; set; }

    [JsonPropertyName("webAuthnPolicyPasswordlessUserVerificationRequirement")]
    public string WebAuthnPolicyPasswordlessUserVerificationRequirement { get; set; }

    [JsonPropertyName("webAuthnPolicyPasswordlessCreateTimeout")]
    public int? WebAuthnPolicyPasswordlessCreateTimeout { get; set; }

    [JsonPropertyName("webAuthnPolicyPasswordlessAvoidSameAuthenticatorRegister")]
    public bool? WebAuthnPolicyPasswordlessAvoidSameAuthenticatorRegister { get; set; }

    [JsonPropertyName("webAuthnPolicyPasswordlessAcceptableAaguids")]
    public IEnumerable<string> WebAuthnPolicyPasswordlessAcceptableAaguids { get; set; }

    [JsonPropertyName("webAuthnPolicyPasswordlessExtraOrigins")]
    public IEnumerable<string> WebAuthnPolicyPasswordlessExtraOrigins { get; set; }

    [JsonPropertyName("webAuthnPolicyPasswordlessPasskeysEnabled")]
    public bool? WebAuthnPolicyPasswordlessPasskeysEnabled { get; set; }

    [JsonPropertyName("users")]
    public IEnumerable<User> Users { get; set; }

    [JsonPropertyName("federatedUsers")]
    public IEnumerable<User> FederatedUsers { get; set; }

    [JsonPropertyName("clients")]
    public IEnumerable<Client> Clients { get; set; }

    [JsonPropertyName("clientScopes")]
    public IEnumerable<ClientScope> ClientScopes { get; set; }

    [JsonPropertyName("defaultDefaultClientScopes")]
    public IEnumerable<string> DefaultDefaultClientScopes { get; set; }

    [JsonPropertyName("defaultOptionalClientScopes")]
    public IEnumerable<string> DefaultOptionalClientScopes { get; set; }

    [JsonPropertyName("browserSecurityHeaders")]
    public BrowserSecurityHeaders BrowserSecurityHeaders { get; set; }

    [JsonPropertyName("smtpServer")]
    public SmtpServer SmtpServer { get; set; }

    [JsonPropertyName("loginTheme")]
    public string? LoginTheme { get; set; }

    [JsonPropertyName("accountTheme")]
    public string? AccountTheme { get; set; }

    [JsonPropertyName("adminTheme")]
    public string? AdminTheme { get; set; }

    [JsonPropertyName("emailTheme")]
    public string? EmailTheme { get; set; }

    [JsonPropertyName("eventsEnabled")]
    public bool? EventsEnabled { get; set; }

    [JsonPropertyName("eventsExpiration")]
    public long? EventsExpiration { get; set; }

    [JsonPropertyName("eventsListeners")]
    public IEnumerable<string> EventsListeners { get; set; }

    [JsonPropertyName("enabledEventTypes")]
    public IEnumerable<string> EnabledEventTypes { get; set; }

    [JsonPropertyName("adminEventsEnabled")]
    public bool? AdminEventsEnabled { get; set; }

    [JsonPropertyName("adminEventsDetailsEnabled")]
    public bool? AdminEventsDetailsEnabled { get; set; }

    [JsonPropertyName("identityProviders")]
    public IEnumerable<IdentityProvider> IdentityProviders { get; set; }

    [JsonPropertyName("identityProviderMappers")]
    public IEnumerable<IdentityProviderMapper> IdentityProviderMappers { get; set; }

    [JsonPropertyName("protocolMappers")]
    public IEnumerable<ProtocolMapper> ProtocolMappers { get; set; }

    [JsonPropertyName("internationalizationEnabled")]
    public bool? InternationalizationEnabled { get; set; }

    [JsonPropertyName("supportedLocales")]
    public IEnumerable<string> SupportedLocales { get; set; }

    [JsonPropertyName("defaultLocale")]
    public string? DefaultLocale { get; set; }

    [JsonPropertyName("authenticationFlows")]
    public IEnumerable<AuthenticationFlow> AuthenticationFlows { get; set; }

    [JsonPropertyName("authenticatorConfig")]
    public IEnumerable<AuthenticatorConfig> AuthenticatorConfig { get; set; }

    [JsonPropertyName("requiredActions")]
    public IEnumerable<RequiredActionProvider> RequiredActions { get; set; }

    [JsonPropertyName("browserFlow")]
    public string BrowserFlow { get; set; }

    [JsonPropertyName("registrationFlow")]
    public string RegistrationFlow { get; set; }

    [JsonPropertyName("directGrantFlow")]
    public string DirectGrantFlow { get; set; }

    [JsonPropertyName("resetCredentialsFlow")]
    public string ResetCredentialsFlow { get; set; }

    [JsonPropertyName("clientAuthenticationFlow")]
    public string ClientAuthenticationFlow { get; set; }

    [JsonPropertyName("dockerAuthenticationFlow")]
    public string DockerAuthenticationFlow { get; set; }

    [JsonPropertyName("firstBrokerLoginFlow")]
    public string FirstBrokerLoginFlow { get; set; }

    [JsonPropertyName("attributes")]
    public Attributes Attributes { get; set; }

    [JsonPropertyName("keycloakVersion")]
    public string KeycloakVersion { get; set; }

    [JsonPropertyName("userManagedAccessAllowed")]
    public bool? UserManagedAccessAllowed { get; set; }

    [JsonPropertyName("organizationsEnabled")]
    public bool? OrganizationsEnabled { get; set; }

    [JsonPropertyName("organizations")]
    public IEnumerable<Organization>? Organizations { get; set; }

    [JsonPropertyName("verifiableCredentialsEnabled")]
    public bool? VerifiableCredentialsEnabled { get; set; }

    [JsonPropertyName("adminPermissionsEnabled")]
    public bool? AdminPermissionsEnabled { get; set; }

    [Obsolete (message: "Marked as 'deprecated' in Keycloak OpenAPI spec")]
    [JsonPropertyName("social")]
    public bool? Social { get; set; }

    [Obsolete (message: "Marked as 'deprecated' in Keycloak OpenAPI spec")]
    [JsonPropertyName("updateProfileOnInitialSocialLogin")]
    public bool? UpdateProfileOnInitialSocialLogin { get; set; }

    [Obsolete (message: "Marked as 'deprecated' in Keycloak OpenAPI spec")]
    [JsonPropertyName("socialProviders")]
    public Dictionary<string, string> SocialProviders { get; set; }
}
