﻿namespace Keycloak.Net.Models.IdentityProviders;

public class Config
{
	[JsonPropertyName("hideOnLoginPage")]
	public string HideOnLoginPage { get; set; }
	[JsonPropertyName("clientSecret")]
	public string ClientSecret { get; set; }
	[JsonPropertyName("clientId")]
	public string ClientId { get; set; }
	[JsonPropertyName("disableUserInfo")]
	public string DisableUserInfo { get; set; }
	[JsonPropertyName("useJwksUrl")]
	public string UseJwksUrl { get; set; }
}