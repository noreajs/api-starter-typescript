export type JwtTokenReservedClaimType =
  | "iss"
  | "sub"
  | "aud"
  | "exp"
  | "nbf"
  | "iat"
  | "jti"
  | "azp"
  | "nonce"
  | "auth_time"
  | "at_hash"
  | "c_hash"
  | "acr"
  | "amr"
  | "sub_jwk"
  | "cnf"
  | "sip_from_tag"
  | "sip_date"
  | "sip_callid"
  | "sip_cseq_num"
  | "sip_via_branch"
  | "orig"
  | "dest"
  | "mky"
  | "events"
  | "toe"
  | "txn"
  | "rph"
  | "sid"
  | "vot"
  | "vtm"
  | "attest"
  | "origid"
  | "act"
  | "scope"
  | "client_id"
  | "may_act"
  | "jcard"
  | "at_use_nbr";

export type JwtTokenStandardClaimType =
  | "name"
  | "given_name"
  | "family_name"
  | "middle_name"
  | "nickname"
  | "preferred_username"
  | "profile"
  | "picture"
  | "website"
  | "email"
  | "email_verified"
  | "gender"
  | "birthdate"
  | "zoneinfo"
  | "locale"
  | "phone_number"
  | "phone_number_verified"
  | "address"
  | "updated_at";

export type JwtTokenAddressClaimType =
  | "formatted"
  | "street_address"
  | "locality"
  | "region"
  | "postal_code"
  | "country";

export type IJwtTokenPayload = {
  [key in
    | JwtTokenReservedClaimType
    | JwtTokenStandardClaimType
    | JwtTokenAddressClaimType]: any;
};

export default IJwtTokenPayload;
