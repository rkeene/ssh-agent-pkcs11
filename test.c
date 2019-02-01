#include "libssh-agent-client.h"
#include "mypkcs11.h"

#include <sys/types.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

static char *pkcs11_attribute_to_name(CK_ATTRIBUTE_TYPE attrib) {
	static char retbuf[1024];

	switch (attrib) {
		case 0x00000000: return "CKA_CLASS";
		case 0x00000001: return "CKA_TOKEN";
		case 0x00000002: return "CKA_PRIVATE";
		case 0x00000003: return "CKA_LABEL";
		case 0x00000010: return "CKA_APPLICATION";
		case 0x00000011: return "CKA_VALUE";
		case 0x00000012: return "CKA_OBJECT_ID";
		case 0x00000080: return "CKA_CERTIFICATE_TYPE";
		case 0x00000081: return "CKA_ISSUER";
		case 0x00000082: return "CKA_SERIAL_NUMBER";
		case 0x00000083: return "CKA_AC_ISSUER";
		case 0x00000084: return "CKA_OWNER";
		case 0x00000085: return "CKA_ATTR_TYPES";
		case 0x00000086: return "CKA_TRUSTED";
		case 0x00000100: return "CKA_KEY_TYPE";
		case 0x00000101: return "CKA_SUBJECT";
		case 0x00000102: return "CKA_ID";
		case 0x00000103: return "CKA_SENSITIVE";
		case 0x00000104: return "CKA_ENCRYPT";
		case 0x00000105: return "CKA_DECRYPT";
		case 0x00000106: return "CKA_WRAP";
		case 0x00000107: return "CKA_UNWRAP";
		case 0x00000108: return "CKA_SIGN";
		case 0x00000109: return "CKA_SIGN_RECOVER";
		case 0x0000010A: return "CKA_VERIFY";
		case 0x0000010B: return "CKA_VERIFY_RECOVER";
		case 0x0000010C: return "CKA_DERIVE";
		case 0x00000110: return "CKA_START_DATE";
		case 0x00000111: return "CKA_END_DATE";
		case 0x00000120: return "CKA_MODULUS";
		case 0x00000121: return "CKA_MODULUS_BITS";
		case 0x00000122: return "CKA_PUBLIC_EXPONENT";
		case 0x00000123: return "CKA_PRIVATE_EXPONENT";
		case 0x00000124: return "CKA_PRIME_1";
		case 0x00000125: return "CKA_PRIME_2";
		case 0x00000126: return "CKA_EXPONENT_1";
		case 0x00000127: return "CKA_EXPONENT_2";
		case 0x00000128: return "CKA_COEFFICIENT";
		case 0x00000130: return "CKA_PRIME";
		case 0x00000131: return "CKA_SUBPRIME";
		case 0x00000132: return "CKA_BASE";
		case 0x00000133: return "CKA_PRIME_BITS";
		case 0x00000134: return "CKA_SUB_PRIME_BITS";
		case 0x00000160: return "CKA_VALUE_BITS";
		case 0x00000161: return "CKA_VALUE_LEN";
		case 0x00000162: return "CKA_EXTRACTABLE";
		case 0x00000163: return "CKA_LOCAL";
		case 0x00000164: return "CKA_NEVER_EXTRACTABLE";
		case 0x00000165: return "CKA_ALWAYS_SENSITIVE";
		case 0x00000166: return "CKA_KEY_GEN_MECHANISM";
		case 0x00000170: return "CKA_MODIFIABLE";
		case 0x00000180: return "CKA_EC_PARAMS";
		case 0x00000181: return "CKA_EC_POINT";
		case 0x00000200: return "CKA_SECONDARY_AUTH";
		case 0x00000201: return "CKA_AUTH_PIN_FLAGS";
		case 0x00000300: return "CKA_HW_FEATURE_TYPE";
		case 0x00000301: return "CKA_RESET_ON_INIT";
		case 0x00000302: return "CKA_HAS_RESET";
	}

	snprintf(retbuf, sizeof(retbuf), "0x%08lx", (unsigned long) attrib);
	retbuf[sizeof(retbuf) - 1] = '\0';

	return(retbuf);
}

int main_ssh_agent_client(void) {
	struct ssh_agent_identity *identities = NULL, *currid;
	unsigned char buf[16384];
	ssize_t buflen;
	int fd = -1, i;

	fd = ssh_agent_connect_socket(NULL);
	if (fd < 0) {
		return(1);
	}

	identities = ssh_agent_getidentities(fd);
	if (!identities) {
		return(1);
	}

	buflen = ssh_agent_sign(fd, (unsigned char *) "Test", strlen("Test"), buf, sizeof(buf), &identities[0], 1);
	printf("Signed(SHA1(\"Test\")): ");
	for (i = 0; i < buflen; i++) {
		printf("%02x ", buf[i]);
	}
	printf("\n");

	buflen = ssh_agent_sign(fd, (unsigned char *) "Test", strlen("Test"), buf, sizeof(buf), &identities[0], 0);
	printf("Signed(\"Test\"): ");
	for (i = 0; i < buflen; i++) {
		printf("%02x ", buf[i]);
	}
	printf("\n");

	buflen = ssh_agent_decrypt(fd, (unsigned char *) "\x1b\x88\xa2\xc1\x7e\xde\x5a\xc8\x1f\x5f\x2a\xc1\x72\xd1\x36\x77\x5b\x66\x0a\x17\x35\x9b\xe1\x71\x05\x88\x1f\xcb\xb4\x7f\xbf\x64\xd5\x9e\xcc\x8d\x0f\x88\xf1\xa0\xef\xc9\xa7\x68\xd3\x98\x1f\x8d\xeb\x36\xc0\xb4\xd6\x86\xcd\x2b\x86\x69\x9c\x7a\xa8\x31\x04\x23\xb7\x0a\x50\xf2\xb1\x83\x01\xe8\x5b\x80\x25\x1f\x85\x70\x3c\x65\x2b\x07\x32\x1d\x30\xde\x96\xe8\xff\x56\x39\x20\xda\x26\xc6\x2a\x67\x9f\x83\x1d\x19\x90\xef\x4b\x04\xa0\x75\x05\xd7\x45\xc1\xb6\x52\x3b\xdd\xf2\x05\x25\x33\xd0\x3d\xa0\x3d\xb6\x70\xeb\xda\xf4\xd2\x27\x22\xdc\x54\x0a\x7a\xcb\xec\x35\x6c\x43\x2d\xed\x53\xa9\x95\xb1\x3d\x7a\x26\x27\x04\x8f\xcd\x74\x81\xdd\x61\x73\xd4\x5d\xc6\xd0\x97\xca\x29\x97\x3b\x2c\x49\x95\xdf\x5d\x48\x3d\x79\x60\xce\xb9\xec\xff\xed\xb9\x72\xf1\x0e\x0a\xe4\x80\xc1\x95\x65\xab\x26\xee\xfd\x80\x18\xb9\x51\x57\x88\xa6\xc1\x00\xda\x75\xd8\xb3\xc3\x0e\x2d\x3d\x56\x3e\xbd\xdd\x15\xb7\xc5\x30\x59\xdf\xf3\x7d\xd0\x5d\x9e\xc1\x86\x5b\xb5\x4e\x3e\xb1\xd4\x64\xd4\x7f\xe6\x93\x81\xff\xbf\xdd\x09\x60\x0f\x00\x8b\x48\x1b\x04\xbf\xb7\x9d\xf6", 256, buf, sizeof(buf), &identities[0]);
	printf("Decrypted: %.*s\n", buflen, buf);

	for (currid = identities; currid->blob; currid++) {
		buflen = ssh_agent_getcert(fd, buf, sizeof(buf), currid);
		if (buflen < 0) {
			continue;
		}

		printf("Cert: ");
		for (i = 0; i < buflen; i++) {
			printf("%02x ", buf[i]);
		}
		printf("\n");
	}

	ssh_agent_freeidentities(identities);

	close(fd);

	return(0);
}

int main_ssh_agent_pkcs11_provider(void) {
	CK_C_INITIALIZE_ARGS initargs;
	CK_INFO clientinfo;
	CK_ULONG numSlots, currSlot;
	CK_SLOT_ID_PTR slots;
	CK_SLOT_INFO slotInfo;
	CK_TOKEN_INFO tokenInfo;
	CK_SESSION_HANDLE hSession;
	CK_SESSION_INFO sessionInfo;
	CK_OBJECT_HANDLE hObject, *privateKeyObjects_root, *privateKeyObjects, *currPrivKey;
	CK_ULONG ulObjectCount;
	CK_ATTRIBUTE template[] = {
	                           {CKA_CLASS, NULL, 0},
	                           {CKA_TOKEN, NULL, 0},
	                           {CKA_LABEL, NULL, 0},
	                           {CKA_PRIVATE, NULL, 0},
	                           {CKA_ID, NULL, 0},
	                           {CKA_SERIAL_NUMBER, NULL, 0},
	                           {CKA_SUBJECT, NULL, 0},
	                           {CKA_ISSUER, NULL, 0},
	                           {CKA_PRIVATE, NULL, 0},
	                           {CKA_CERTIFICATE_TYPE, NULL, 0},
	                           {CKA_KEY_TYPE, NULL, 0},
	                           {CKA_SIGN, NULL, 0},
	                           {CKA_VALUE, NULL, 0}
	                          }, *curr_attr;
	CK_ULONG curr_attr_idx;
	CK_ULONG byte_idx;
	CK_UTF8CHAR user_pin[1024], *pucValue;
	CK_OBJECT_CLASS objectClass;
	CK_BYTE signature[1024], encrypted_buf[16384], decrypted_buf[16384];
	CK_ULONG signature_len, encrypted_buflen, decrypted_buflen;
	CK_MECHANISM mechanism = {CKM_RSA_PKCS, NULL, 0};
	CK_RV chk_rv;
	int i;

	privateKeyObjects = malloc(sizeof(*privateKeyObjects) * 1024);
	privateKeyObjects_root = privateKeyObjects;
	for (i = 0; i < 1024; i++) {
		privateKeyObjects[i] = CK_INVALID_HANDLE;
	}

	initargs.CreateMutex = NULL;
	initargs.DestroyMutex = NULL;
	initargs.LockMutex = NULL;
	initargs.UnlockMutex = NULL;
	initargs.flags = CKF_OS_LOCKING_OK;
	initargs.pReserved = NULL;
	initargs.LibraryParameters = NULL;

	chk_rv = C_Initialize(&initargs);
	if (chk_rv != CKR_OK) {
		initargs.CreateMutex = NULL;
		initargs.DestroyMutex = NULL;
		initargs.LockMutex = NULL;
		initargs.UnlockMutex = NULL;
		initargs.flags = 0;
		initargs.pReserved = NULL;

		chk_rv = C_Initialize(&initargs);
		if (chk_rv != CKR_OK) {
			printf("C_Initialize() failed.");

			return(1);
		}
	}

	chk_rv = C_GetInfo(&clientinfo);
	if (chk_rv != CKR_OK) {
		return(1);
	}

	printf("PKCS#11 Client Version: %i.%i, Library Version %i.%i\n", clientinfo.cryptokiVersion.major, clientinfo.cryptokiVersion.minor, clientinfo.libraryVersion.major, clientinfo.libraryVersion.minor);
	printf("PKCS#11 ManufID: %.*s, LibraryDesc: %.*s\n", 32, clientinfo.manufacturerID, 32, clientinfo.libraryDescription);

	chk_rv = C_GetSlotList(FALSE, NULL, &numSlots);
	if (chk_rv != CKR_OK) {
		return(1);
	}

	printf("Number of Slots: %lu\n", numSlots);

	slots = malloc(sizeof(*slots) * numSlots);

	chk_rv = C_GetSlotList(FALSE, slots, &numSlots);
	if (chk_rv != CKR_OK) {
		return(1);
	}

	for (currSlot = 0; currSlot < numSlots; currSlot++) {
		printf("  Slot %lu:\n", currSlot);

		chk_rv = C_GetSlotInfo(slots[currSlot], &slotInfo);
		if (chk_rv != CKR_OK) {
			return(1);
		}

		printf("    Desc   : %.*s\n", 32, slotInfo.slotDescription);
		printf("    ManufID: %.*s\n", 32, slotInfo.manufacturerID);
		printf("    HWVers : %i.%i\n", slotInfo.hardwareVersion.major, slotInfo.hardwareVersion.minor);
		printf("    FWVers : %i.%i\n", slotInfo.firmwareVersion.major, slotInfo.firmwareVersion.minor);
		printf("    Flags  : ");
		if ((slotInfo.flags & CKF_TOKEN_PRESENT) == CKF_TOKEN_PRESENT) {
			printf("CKF_TOKEN_PRESENT ");
		}
		if ((slotInfo.flags & CKF_REMOVABLE_DEVICE) == CKF_REMOVABLE_DEVICE) {
			printf("CKF_REMOVABLE_DEVICE ");
		}
		if ((slotInfo.flags & CKF_HW_SLOT) == CKF_HW_SLOT) {
			printf("CKF_HW_SLOT ");
		}
		printf("\n");

		if ((slotInfo.flags & CKF_TOKEN_PRESENT) == CKF_TOKEN_PRESENT) {
			printf("    Token:\n");

			chk_rv = C_GetTokenInfo(slots[currSlot], &tokenInfo);
			if (chk_rv != CKR_OK) {
				return(1);
			}

			printf("      Label  : %.*s\n", 32, tokenInfo.label);
			printf("      ManufID: %.*s\n", 32, tokenInfo.manufacturerID);
			printf("      Model  : %.*s\n", 16, tokenInfo.model);
			printf("      SerNo  : %.*s\n", 16, tokenInfo.serialNumber);
			printf("      HWVers : %i.%i\n", tokenInfo.hardwareVersion.major, tokenInfo.hardwareVersion.minor);
			printf("      FWVers : %i.%i\n", tokenInfo.firmwareVersion.major, tokenInfo.firmwareVersion.minor);
			printf("      Flags  : ");
			if ((tokenInfo.flags & CKF_RNG) == CKF_RNG) {
				printf("CKF_RNG ");
			}
			if ((tokenInfo.flags & CKF_WRITE_PROTECTED) == CKF_WRITE_PROTECTED) {
				printf("CKF_WRITE_PROTECTED ");
			}
			if ((tokenInfo.flags & CKF_LOGIN_REQUIRED) == CKF_LOGIN_REQUIRED) {
				printf("CKF_LOGIN_REQUIRED ");
			}
			if ((tokenInfo.flags & CKF_USER_PIN_INITIALIZED) == CKF_USER_PIN_INITIALIZED) {
				printf("CKF_USER_PIN_INITIALIZED ");
			}
			if ((tokenInfo.flags & CKF_RESTORE_KEY_NOT_NEEDED) == CKF_RESTORE_KEY_NOT_NEEDED) {
				printf("CKF_RESTORE_KEY_NOT_NEEDED ");
			}
			if ((tokenInfo.flags & CKF_CLOCK_ON_TOKEN) == CKF_CLOCK_ON_TOKEN) {
				printf("CKF_CLOCK_ON_TOKEN ");
			}
			if ((tokenInfo.flags & CKF_PROTECTED_AUTHENTICATION_PATH) == CKF_PROTECTED_AUTHENTICATION_PATH) {
				printf("CKF_PROTECTED_AUTHENTICATION_PATH ");
			}
			if ((tokenInfo.flags & CKF_DUAL_CRYPTO_OPERATIONS) == CKF_DUAL_CRYPTO_OPERATIONS) {
				printf("CKF_DUAL_CRYPTO_OPERATIONS ");
			}
			if ((tokenInfo.flags & CKF_TOKEN_INITIALIZED) == CKF_TOKEN_INITIALIZED) {
				printf("CKF_TOKEN_INITIALIZED ");
			}
			if ((tokenInfo.flags & CKF_SECONDARY_AUTHENTICATION) == CKF_SECONDARY_AUTHENTICATION) {
				printf("CKF_SECONDARY_AUTHENTICATION ");
			}
			if ((tokenInfo.flags & CKF_USER_PIN_COUNT_LOW) == CKF_USER_PIN_COUNT_LOW) {
				printf("CKF_USER_PIN_COUNT_LOW ");
			}
			if ((tokenInfo.flags & CKF_USER_PIN_FINAL_TRY) == CKF_USER_PIN_FINAL_TRY) {
				printf("CKF_USER_PIN_FINAL_TRY ");
			}
			if ((tokenInfo.flags & CKF_USER_PIN_LOCKED) == CKF_USER_PIN_LOCKED) {
				printf("CKF_USER_PIN_LOCKED ");
			}
			if ((tokenInfo.flags & CKF_USER_PIN_TO_BE_CHANGED) == CKF_USER_PIN_TO_BE_CHANGED) {
				printf("CKF_USER_PIN_TO_BE_CHANGED ");
			}
			if ((tokenInfo.flags & CKF_SO_PIN_COUNT_LOW) == CKF_SO_PIN_COUNT_LOW) {
				printf("CKF_SO_PIN_COUNT_LOW ");
			}
			if ((tokenInfo.flags & CKF_SO_PIN_FINAL_TRY) == CKF_SO_PIN_FINAL_TRY) {
				printf("CKF_SO_PIN_FINAL_TRY ");
			}
			if ((tokenInfo.flags & CKF_SO_PIN_LOCKED) == CKF_SO_PIN_LOCKED) {
				printf("CKF_SO_PIN_LOCKED ");
			}
			if ((tokenInfo.flags & CKF_SO_PIN_TO_BE_CHANGED) == CKF_SO_PIN_TO_BE_CHANGED) {
				printf("CKF_SO_PIN_TO_BE_CHANGED ");
			}
			printf("\n");
		}
	}

	chk_rv = C_OpenSession(slots[0], CKF_SERIAL_SESSION, NULL, NULL, &hSession);
	if (chk_rv == CKR_OK) {
		if ((tokenInfo.flags & CKF_LOGIN_REQUIRED) == CKF_LOGIN_REQUIRED) {
			printf("** ENTER PIN: ");
			fflush(stdout);

			fgets((char *) user_pin, sizeof(user_pin), stdin);
			while (user_pin[strlen((char *) user_pin) - 1] < ' ') {
				user_pin[strlen((char *) user_pin) - 1] = '\0';
			}

			chk_rv = C_Login(hSession, CKU_USER, user_pin, strlen((char *) user_pin));
		} else {
			chk_rv = C_Login(hSession, CKU_USER, NULL, 0);
		}
		if (chk_rv == CKR_OK) {
			printf("Login to device succeed.\n");
		} else {
			printf("Login to device failed.\n");
		}

		chk_rv = C_GetSessionInfo(hSession, &sessionInfo);
		if (chk_rv == CKR_OK) {
			printf("Session Info:\n");
			printf("  Slot ID: %lu\n", (unsigned long) sessionInfo.slotID);
			printf("  Dev Err: %lu\n", (unsigned long) sessionInfo.ulDeviceError);

			printf("  State  : ");
			if (sessionInfo.state == CKS_RO_PUBLIC_SESSION) {
				printf("CKS_RO_PUBLIC_SESSION\n");
			} else if (sessionInfo.state == CKS_RO_USER_FUNCTIONS) {
				printf("CKS_RO_USER_FUNCTIONS\n");
			} else if (sessionInfo.state == CKS_RW_PUBLIC_SESSION) {
				printf("CKS_RW_PUBLIC_SESSION\n");
			} else if (sessionInfo.state == CKS_RW_USER_FUNCTIONS) {
				printf("CKS_RW_USER_FUNCTIONS\n");
			} else if (sessionInfo.state == CKS_RO_PUBLIC_SESSION) {
				printf("CKS_RW_SO_FUNCTIONS\n");
			} else {
				printf("Unknown (%lu)", (unsigned long) sessionInfo.state);
			}

			printf("  Flags  : ");
			if ((sessionInfo.flags & CKF_RW_SESSION) == CKF_RW_SESSION) {
				printf("CKF_RW_SESSION ");
			}
			if ((sessionInfo.flags & CKF_SERIAL_SESSION) == CKF_SERIAL_SESSION) {
				printf("CKF_SERIAL_SESSION ");
			}
			printf("\n");
		} else {
			printf("GetSessionInfo() failed.\n");
		}

		chk_rv = C_FindObjectsInit(hSession, NULL, 0);
		if (chk_rv == CKR_OK) {
			while (1) {
				chk_rv = C_FindObjects(hSession, &hObject, 1, &ulObjectCount);
				if (chk_rv != CKR_OK) {
					printf("FindObjects() failed.\n");
					break;
				}

				if (ulObjectCount == 0) {
					break;
				}

				if (ulObjectCount != 1) {
					printf("FindObjects() returned a weird number of objects.  Asked for 1, got %lu.\n", ulObjectCount);
					break;
				}

				printf("  Object Info (object %lu):\n", (unsigned long) hObject);

				for (curr_attr_idx = 0; curr_attr_idx < (sizeof(template) / sizeof(template[0])); curr_attr_idx++) {
					curr_attr = &template[curr_attr_idx];
					if (curr_attr->pValue) {
						free(curr_attr->pValue);
					}

					curr_attr->pValue = NULL;
				}

				chk_rv = C_GetAttributeValue(hSession, hObject, &template[0], sizeof(template) / sizeof(template[0]));
				if (chk_rv == CKR_ATTRIBUTE_TYPE_INVALID || chk_rv == CKR_ATTRIBUTE_SENSITIVE || chk_rv == CKR_BUFFER_TOO_SMALL) {
					chk_rv = CKR_OK;
				}

				if (chk_rv == CKR_OK) {
					for (curr_attr_idx = 0; curr_attr_idx < (sizeof(template) / sizeof(template[0])); curr_attr_idx++) {
						curr_attr = &template[curr_attr_idx];

						if (((CK_LONG) curr_attr->ulValueLen) != ((CK_LONG) -1)) {
							curr_attr->pValue = malloc(curr_attr->ulValueLen);
						}
					}

					chk_rv = C_GetAttributeValue(hSession, hObject, &template[0], sizeof(template) / sizeof(template[0]));
					if (chk_rv == CKR_OK || chk_rv == CKR_ATTRIBUTE_SENSITIVE || chk_rv == CKR_ATTRIBUTE_TYPE_INVALID || chk_rv == CKR_BUFFER_TOO_SMALL) {
						for (curr_attr_idx = 0; curr_attr_idx < (sizeof(template) / sizeof(template[0])); curr_attr_idx++) {
							curr_attr = &template[curr_attr_idx];

							if (curr_attr->pValue) {
								switch (curr_attr->type) {
									case CKA_LABEL:
										printf("    [%lu] %20s: %.*s\n", hObject, pkcs11_attribute_to_name(curr_attr->type), (int) curr_attr->ulValueLen, (char *) curr_attr->pValue);
										break;
									case CKA_CLASS:
										objectClass = *((CK_OBJECT_CLASS *) curr_attr->pValue);

										if (objectClass == CKO_PRIVATE_KEY) {
											*privateKeyObjects = hObject;
											privateKeyObjects++;
										}
									case CKA_TOKEN:
									case CKA_ID:
									case CKA_SERIAL_NUMBER:
									case CKA_PRIVATE:
									case CKA_CERTIFICATE_TYPE:
									case CKA_KEY_TYPE:
									case CKA_SIGN:
									case CKA_DECRYPT:
										pucValue = curr_attr->pValue;

										printf("    [%lu] %20s: ", hObject, pkcs11_attribute_to_name(curr_attr->type));

										for (byte_idx = 0; byte_idx < curr_attr->ulValueLen; byte_idx++) {
											printf("%02x ", (unsigned int) pucValue[byte_idx]);
										}

										printf(";; %p/%lu\n", curr_attr->pValue, curr_attr->ulValueLen);

										break;
									case CKA_SUBJECT:
									case CKA_ISSUER:
										pucValue = curr_attr->pValue;

										printf("    [%lu] %20s: ", hObject, pkcs11_attribute_to_name(curr_attr->type));

										for (byte_idx = 0; byte_idx < curr_attr->ulValueLen; byte_idx++) {
											printf("\\x%02x", (unsigned int) pucValue[byte_idx]);
										}

										printf(" ;; %p/%lu\n", curr_attr->pValue, curr_attr->ulValueLen);

										break;
									default:
										printf("    [%lu] %20s: %p/%lu\n", hObject, pkcs11_attribute_to_name(curr_attr->type), curr_attr->pValue, curr_attr->ulValueLen);

										break;
								}
							} else {
								printf("    [%lu] %20s: (not found)\n", hObject, pkcs11_attribute_to_name(curr_attr->type));
							}

							free(curr_attr->pValue);
							curr_attr->pValue = NULL;
						}
					} else {
						printf("GetAttributeValue()/2 failed.\n");
					}
				} else {
					printf("GetAttributeValue(hObject=%lu)/1 failed (rv = %lu).\n", (unsigned long) hObject, (unsigned long) chk_rv);
				}

			}

			chk_rv = C_FindObjectsFinal(hSession);
			if (chk_rv != CKR_OK) {
				printf("FindObjectsFinal() failed.\n");
			}
		} else {
			printf("FindObjectsInit() failed.\n");
		}

		printf("--- Operations ---\n");

		for (currPrivKey = privateKeyObjects_root; *currPrivKey != CK_INVALID_HANDLE; currPrivKey++) {
			chk_rv = C_SignInit(hSession, &mechanism, *currPrivKey);
			if (chk_rv == CKR_OK) {
				signature_len = sizeof(signature);

				chk_rv = C_Sign(hSession, (CK_BYTE_PTR) "Test", strlen("Test"), (CK_BYTE_PTR) &signature, &signature_len);
				if (chk_rv == CKR_OK) {
					printf("[%04lu/%02lx] Signature: ", (unsigned long) *currPrivKey, (unsigned long) mechanism.mechanism);

					for (byte_idx = 0; byte_idx < signature_len; byte_idx++) {
						printf("%02x ", (unsigned int) signature[byte_idx]);
					}

					printf("\n");
				} else {
					printf("Sign() failed.\n");
				}
			} else {
				printf("SignInit() failed.\n");
			}
		}

		for (currPrivKey = privateKeyObjects_root; *currPrivKey != CK_INVALID_HANDLE; currPrivKey++) {
			chk_rv = C_EncryptInit(hSession, &mechanism, *currPrivKey);
			if (chk_rv == CKR_OK) {
				encrypted_buflen = sizeof(encrypted_buf);

				chk_rv = C_Encrypt(hSession, (CK_BYTE_PTR) "Test", strlen("Test"), encrypted_buf, &encrypted_buflen);
				if (chk_rv == CKR_OK) {
					printf("[%04lu/%02lx] Encrypted(Test): ", (unsigned long) *currPrivKey, (unsigned long) mechanism.mechanism);

					for (byte_idx = 0; byte_idx < encrypted_buflen; byte_idx++) {
						printf("%02x ", (unsigned int) encrypted_buf[byte_idx]);
					}

					printf("\n");
				} else {
					printf("Encrypt() failed.\n");
				}
			} else {
				printf("EncryptInit() failed.\n");
			}
		}

		for (currPrivKey = privateKeyObjects_root; *currPrivKey != CK_INVALID_HANDLE; currPrivKey++) {
			chk_rv = C_DecryptInit(hSession, &mechanism, *currPrivKey);
			if (chk_rv == CKR_OK) {
				decrypted_buflen = sizeof(decrypted_buf);

				chk_rv = C_Decrypt(hSession, (CK_BYTE_PTR) "\x1b\x88\xa2\xc1\x7e\xde\x5a\xc8\x1f\x5f\x2a\xc1\x72\xd1\x36\x77\x5b\x66\x0a\x17\x35\x9b\xe1\x71\x05\x88\x1f\xcb\xb4\x7f\xbf\x64\xd5\x9e\xcc\x8d\x0f\x88\xf1\xa0\xef\xc9\xa7\x68\xd3\x98\x1f\x8d\xeb\x36\xc0\xb4\xd6\x86\xcd\x2b\x86\x69\x9c\x7a\xa8\x31\x04\x23\xb7\x0a\x50\xf2\xb1\x83\x01\xe8\x5b\x80\x25\x1f\x85\x70\x3c\x65\x2b\x07\x32\x1d\x30\xde\x96\xe8\xff\x56\x39\x20\xda\x26\xc6\x2a\x67\x9f\x83\x1d\x19\x90\xef\x4b\x04\xa0\x75\x05\xd7\x45\xc1\xb6\x52\x3b\xdd\xf2\x05\x25\x33\xd0\x3d\xa0\x3d\xb6\x70\xeb\xda\xf4\xd2\x27\x22\xdc\x54\x0a\x7a\xcb\xec\x35\x6c\x43\x2d\xed\x53\xa9\x95\xb1\x3d\x7a\x26\x27\x04\x8f\xcd\x74\x81\xdd\x61\x73\xd4\x5d\xc6\xd0\x97\xca\x29\x97\x3b\x2c\x49\x95\xdf\x5d\x48\x3d\x79\x60\xce\xb9\xec\xff\xed\xb9\x72\xf1\x0e\x0a\xe4\x80\xc1\x95\x65\xab\x26\xee\xfd\x80\x18\xb9\x51\x57\x88\xa6\xc1\x00\xda\x75\xd8\xb3\xc3\x0e\x2d\x3d\x56\x3e\xbd\xdd\x15\xb7\xc5\x30\x59\xdf\xf3\x7d\xd0\x5d\x9e\xc1\x86\x5b\xb5\x4e\x3e\xb1\xd4\x64\xd4\x7f\xe6\x93\x81\xff\xbf\xdd\x09\x60\x0f\x00\x8b\x48\x1b\x04\xbf\xb7\x9d\xf6", 256, decrypted_buf, &decrypted_buflen);
				if (chk_rv == CKR_OK) {
					printf("[%04lu/%02lx] Decrypted(It works!): ", (unsigned long) *currPrivKey, (unsigned long) mechanism.mechanism);

					for (byte_idx = 0; byte_idx < decrypted_buflen; byte_idx++) {
						printf("%02x ", (unsigned int) decrypted_buf[byte_idx]);
					}

					printf("\n");
				} else {
					printf("Decrypt() failed.\n");
				}
			} else {
				printf("DecryptInit() failed.\n");
			}
		}

		chk_rv = C_CloseSession(hSession);
		if (chk_rv != CKR_OK) {
			printf("CloseSession failed.\n");
		}
	} else {
		printf("OpenSession failed.\n");
	}

	C_Finalize(NULL);

	if (slots) {
		free(slots);
	}

	if (privateKeyObjects_root) {
		free(privateKeyObjects_root);
	}

	return(0);
}

int main(void) {
	int retval = 0, ck_retval;

	printf("Testing libssh-agent-client...\n");

	ck_retval = main_ssh_agent_client();

	if (ck_retval != 0) {
		retval = ck_retval;
	}

	printf("Testing libssh-agent-client... DONE. Status = %i\n", ck_retval);

	printf("Testing libssh-agent-pkcs11-provider...\n");

	ck_retval = main_ssh_agent_pkcs11_provider();

	if (ck_retval != 0) {
		retval = ck_retval;
	}

	printf("Testing libssh-agent-pkcs11-provider... DONE. Status = %i\n", ck_retval);

	return(retval);
}
