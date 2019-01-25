package pkcs8

import "encoding/asn1"

var (
	/* CRYPT_PRIVATE_KEYS_ALG_OID_GROUP_ID */
	OID_CP_GOST_PRIVATE_KEYS_V1        = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 37, 1}
	OID_CP_GOST_PRIVATE_KEYS_V2        = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 37, 2}
	OID_CP_GOST_PRIVATE_KEYS_V2_FULL   = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 37, 2, 1}
	OID_CP_GOST_PRIVATE_KEYS_V2_PARTOF = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 37, 2, 2}

	/* CRYPT_HASH_ALG_OID_GROUP_ID */
	OID_CP_GOST_R3411        = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 9}
	OID_CP_GOST_R3411_12_256 = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 2, 2}
	OID_CP_GOST_R3411_12_512 = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 2, 3}

	/* CRYPT_ENCRYPT_ALG_OID_GROUP_ID */
	OID_CP_GOST_28147        = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 21}
	OID_CP_GOST_R3412_2015_M = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 5, 1}
	OID_CP_GOST_R3412_2015_K = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 5, 2}

	/* CRYPT_PUBKEY_ALG_OID_GROUP_ID */
	OID_CP_GOST_R3410         = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 20}
	OID_CP_GOST_R3410EL       = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 19}
	OID_CP_GOST_R3410_12_256  = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 1, 1}
	OID_CP_GOST_R3410_12_512  = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 1, 2}
	OID_CP_DH_EX              = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 99}
	OID_CP_DH_EL              = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 98}
	OID_CP_DH_12_256          = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 6, 1}
	OID_CP_DH_12_512          = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 6, 2}
	OID_CP_GOST_R3410_94_ESDH = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 97}
	OID_CP_GOST_R3410_01_ESDH = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 96}

	/* CRYPT_SIGN_ALG_OID_GROUP_ID */
	OID_CP_GOST_R3411_R3410        = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 4}
	OID_CP_GOST_R3411_R3410EL      = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 3}
	OID_CP_GOST_R3411_12_256_R3410 = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 3, 2}
	OID_CP_GOST_R3411_12_512_R3410 = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 3, 3}

	/* CRYPT_ENHKEY_USAGE_OID_GROUP_ID */
	OID_KP_TLS_PROXY           = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 34, 1}
	OID_KP_RA_CLIENT_AUTH      = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 34, 2}
	OID_KP_WEB_CONTENT_SIGNING = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 34, 3}
	OID_KP_RA_ADMINISTRATOR    = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 34, 4}
	OID_KP_RA_OPERATOR         = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 34, 5}

	/* Qualified Certificate */
	OID_OGRN   = asn1.ObjectIdentifier{1, 2, 643, 100, 1}
	OID_OGRNIP = asn1.ObjectIdentifier{1, 2, 643, 100, 5}
	OID_SNILS  = asn1.ObjectIdentifier{1, 2, 643, 100, 3}
	OID_INN    = asn1.ObjectIdentifier{1, 2, 643, 3, 131, 1, 1}

	/* Signature tool class */
	OID_SIGN_TOOL_KC1 = asn1.ObjectIdentifier{1, 2, 643, 100, 113, 1}
	OID_SIGN_TOOL_KC2 = asn1.ObjectIdentifier{1, 2, 643, 100, 113, 2}
	OID_SIGN_TOOL_KC3 = asn1.ObjectIdentifier{1, 2, 643, 100, 113, 3}
	OID_SIGN_TOOL_KB1 = asn1.ObjectIdentifier{1, 2, 643, 100, 113, 4}
	OID_SIGN_TOOL_KB2 = asn1.ObjectIdentifier{1, 2, 643, 100, 113, 5}
	OID_SIGN_TOOL_KA1 = asn1.ObjectIdentifier{1, 2, 643, 100, 113, 6}

	/* CA tool class */
	OID_CA_TOOL_KC1 = asn1.ObjectIdentifier{1, 2, 643, 100, 114, 1}
	OID_CA_TOOL_KC2 = asn1.ObjectIdentifier{1, 2, 643, 100, 114, 2}
	OID_CA_TOOL_KC3 = asn1.ObjectIdentifier{1, 2, 643, 100, 114, 3}
	OID_CA_TOOL_KB1 = asn1.ObjectIdentifier{1, 2, 643, 100, 114, 4}
	OID_CA_TOOL_KB2 = asn1.ObjectIdentifier{1, 2, 643, 100, 114, 5}
	OID_CA_TOOL_KA1 = asn1.ObjectIdentifier{1, 2, 643, 100, 114, 6}

	/* Our well-known policy ID */
	OID_CEP_BASE_PERSONAL = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 38, 1}
	OID_CEP_BASE_NETWORK  = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 38, 2}

	/* OIDs for HASH */
	OID_GostR3411_94_TestParamSet         = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 30, 0}
	OID_GostR3411_94_CryptoProParamSet    = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 30, 1}
	OID_GostR3411_94_CryptoPro_B_ParamSet = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 30, 2}
	OID_GostR3411_94_CryptoPro_C_ParamSet = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 30, 3}
	OID_GostR3411_94_CryptoPro_D_ParamSet = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 30, 4}

	/* OIDs for Crypt */
	OID_Gost28147_89_TestParamSet                 = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 31, 0}
	OID_Gost28147_89_CryptoPro_A_ParamSet         = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 31, 1}
	OID_Gost28147_89_CryptoPro_B_ParamSet         = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 31, 2}
	OID_Gost28147_89_CryptoPro_C_ParamSet         = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 31, 3}
	OID_Gost28147_89_CryptoPro_D_ParamSet         = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 31, 4}
	OID_Gost28147_89_CryptoPro_Oscar_1_1_ParamSet = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 31, 5}
	OID_Gost28147_89_CryptoPro_Oscar_1_0_ParamSet = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 31, 6}
	OID_Gost28147_89_CryptoPro_RIC_1_ParamSet     = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 31, 7}

	OID_Gost28147_89_TC26_A_ParamSet = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 31, 12}
	OID_Gost28147_89_TC26_B_ParamSet = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 31, 13}
	OID_Gost28147_89_TC26_C_ParamSet = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 31, 14}
	OID_Gost28147_89_TC26_D_ParamSet = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 31, 15}
	OID_Gost28147_89_TC26_E_ParamSet = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 31, 16}
	OID_Gost28147_89_TC26_F_ParamSet = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 31, 17}

	OID_Gost28147_89_TC26_Z_ParamSet = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 5, 1, 1}

	/* OID for Signature 1024*/
	OID_GostR3410_94_CryptoPro_A_ParamSet = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 32, 2}
	OID_GostR3410_94_CryptoPro_B_ParamSet = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 32, 3}
	OID_GostR3410_94_CryptoPro_C_ParamSet = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 32, 4}
	OID_GostR3410_94_CryptoPro_D_ParamSet = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 32, 5}

	/* OID for Signature 512*/
	OID_GostR3410_94_TestParamSet = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 32, 0}

	/* OID for DH 1024*/
	OID_GostR3410_94_CryptoPro_XchA_ParamSet = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 33, 1}
	OID_GostR3410_94_CryptoPro_XchB_ParamSet = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 33, 2}
	OID_GostR3410_94_CryptoPro_XchC_ParamSet = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 33, 3}

	/* OID for EC signature */
	OID_GostR3410_2001_TestParamSet         = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 35, 0}
	OID_GostR3410_2001_CryptoPro_A_ParamSet = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 35, 1}
	OID_GostR3410_2001_CryptoPro_B_ParamSet = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 35, 2}
	OID_GostR3410_2001_CryptoPro_C_ParamSet = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 35, 3}

	OID_tc26_gost_3410_12_256_paramSetA = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 1}

	OID_tc26_gost_3410_12_512_paramSetA = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 2, 1}
	OID_tc26_gost_3410_12_512_paramSetB = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 2, 2}
	OID_tc26_gost_3410_12_512_paramSetC = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 2, 3}

	/* OID for EC DH */
	OID_GostR3410_2001_CryptoPro_XchA_ParamSet = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 36, 0}
	OID_GostR3410_2001_CryptoPro_XchB_ParamSet = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 36, 1}

	/* OIDs for private key container extensions */
	OID_CryptoPro_private_keys_extension_intermediate_store                         = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 37, 3, 1}
	OID_CryptoPro_private_keys_extension_signature_trust_store                      = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 37, 3, 2}
	OID_CryptoPro_private_keys_extension_exchange_trust_store                       = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 37, 3, 3}
	OID_CryptoPro_private_keys_extension_container_friendly_name                    = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 37, 3, 4}
	OID_CryptoPro_private_keys_extension_container_key_usage_period                 = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 37, 3, 5}
	OID_CryptoPro_private_keys_extension_container_uec_symmetric_key_derive_counter = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 37, 3, 6}

	OID_CryptoPro_private_keys_extension_container_primary_key_properties   = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 37, 3, 7}
	OID_CryptoPro_private_keys_extension_container_secondary_key_properties = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 37, 3, 8}

	OID_CryptoPro_private_keys_extension_container_signature_key_usage_period     = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 37, 3, 9}
	OID_CryptoPro_private_keys_extension_container_exchange_key_usage_period      = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 37, 3, 10}
	OID_CryptoPro_private_keys_extension_container_key_time_validity_control_mode = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 37, 3, 11}

	/* OIDs for certificate and CRL extensions */
	OID_CryptoPro_extensions_certificate_and_crl_matching_technique = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 49, 1}
	CPOID_SubjectSignTool                                           = asn1.ObjectIdentifier{1, 2, 643, 100, 111}
	CPOID_IssuerSignTool                                            = asn1.ObjectIdentifier{1, 2, 643, 100, 112}

	/* OIDs for signing certificate attributes */
	CPOID_RSA_SMIMEaaSigningCertificate   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 12}
	CPOID_RSA_SMIMEaaSigningCertificateV2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}
	CPOID_RSA_SMIMEaaETSotherSigCert      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 19}
)
