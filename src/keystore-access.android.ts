const application = require("application");
import { ad } from "tns-core-modules/utils/utils";
import { BiometricIDAvailableResult, ERROR_CODES, KeystoreAccessApi } from "./keystore-access.common";
import KeyguardManager = android.app.KeyguardManager;
import OnClickListener = android.content.DialogInterface.OnClickListener;
import BiometricPrompt = android.hardware.biometrics.BiometricPrompt;
import Build = android.os.Build;
import PreferenceManager = android.preference.PreferenceManager;
import KeyGenParameterSpec = android.security.keystore.KeyGenParameterSpec;
import KeyProperties = android.security.keystore.KeyProperties;
import Base64 = android.util.Base64;
import BiometricPromptX = androidx.biometric.BiometricPrompt;
import FingerprintManagerCompat = androidx.core.hardware.fingerprint.FingerprintManagerCompat;
import Cipher = javax.crypto.Cipher;
import KeyGenerator = javax.crypto.KeyGenerator;
import SecretKey = javax.crypto.SecretKey;

export class KeystoreAccess implements KeystoreAccessApi {
  private cancellationSignal: android.os.CancellationSignal | androidx.core.os.CancellationSignal;

  available(): Promise<BiometricIDAvailableResult> {
    this.stopListening(); // Somebody may be listening in, always stop listening before anything else
    return new Promise((resolve, reject) => {
      try {
        const keyguardManager: KeyguardManager = ad.getApplicationContext().getSystemService("keyguard");
        if (!keyguardManager || !keyguardManager.isKeyguardSecure()) {
          resolve({any: false});
          return;
        }
        // The fingerprint API is only available from Android 6.0 (M, Api level 23)
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
          resolve({any: false, reason: "Your api version doesn't support fingerprint authentication"});
          return;
        }

        const fingerprintManager = FingerprintManagerCompat.from(ad.getApplicationContext());
        if (!fingerprintManager.isHardwareDetected()) {
          // Device doesn't support fingerprint authentication
          resolve({any: false, reason: "Device doesn't support fingerprint authentication"});
        } else if (!fingerprintManager.hasEnrolledFingerprints()) {
          // User hasn't enrolled any fingerprints to authenticate with
          resolve({any: false, reason: "User hasn't enrolled any fingerprints to authenticate with"});
        } else {
          resolve({any: true, touch: true});
        }
      } catch (ex) {
        console.log(`fingerprint-auth.available: ${ex}`);
        reject(ex);
      }
    });
  }

  storeDataWithFingerprint(keystoreKeyAlias: string, data: string, dialogText: { title: string, negativeButton: string }): Promise<void> {
    this.stopListening(); // Somebody may be listening in, always stop listening before anything else
    return new Promise((resolve, reject) => {
      try {
        EncryptionUtils.createKey(keystoreKeyAlias);
        this.startListening(resolve, reject, dialogText, true, keystoreKeyAlias, data);
      } catch (ex) {
        console.trace(ex);
        this.deleteFingerprintEncryptedData(keystoreKeyAlias);
        reject({
          code: ERROR_CODES.DEVELOPER_ERROR,
          message: ex.message,
        });
      }
    });
  }

  retrieveDataWithFingerprint(keystoreKeyAlias: string, dialogText: { title: string, negativeButton: string }): Promise<string> {
    this.stopListening(); // Somebody may be listening in, always stop listening before anything else
    return new Promise((resolve, reject) => {
      try {
        this.startListening(resolve, reject, dialogText, false, keystoreKeyAlias);
      } catch (ex) {
        this.deleteFingerprintEncryptedData(keystoreKeyAlias);
        reject({
          code: ERROR_CODES.DEVELOPER_ERROR,
          message: ex.message,
        });
      }
    });
  }

  fingerprintEncryptedDataExists(keystoreKeyAlias: string): boolean {
    this.stopListening(); // Somebody may be listening in, always stop listening before anything else
    const preferences = PreferenceManager.getDefaultSharedPreferences(ad.getApplicationContext());
    return preferences.contains(KeystoreAccess.name + keystoreKeyAlias);
  }

  deleteFingerprintEncryptedData(keystoreKeyAlias: string): void {
    this.stopListening(); // Somebody may be listening in, always stop listening before anything else
    const preferences = PreferenceManager.getDefaultSharedPreferences(ad.getApplicationContext());
    preferences.edit().remove(KeystoreAccess.name + keystoreKeyAlias).apply();
  }

  cleanup(): void {
    this.stopListening();
  }

  private startListening(promiseResolve: any, promiseReject: any, dialogText: { title: string, negativeButton: string }, cipherInEncryptMode: boolean, keystoreKeyAlias: string, data?: string) {
    let cipher;
    try {
      cipher = EncryptionUtils.initCipher(cipherInEncryptMode ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, keystoreKeyAlias);
    } catch (ex) {
      if (ex instanceof android.security.keystore.KeyPermanentlyInvalidatedException) {
        promiseReject({
          code: ERROR_CODES.TAMPERED_WITH,
          message: ex.getMessage(),
        });
      } else {
        promiseReject({
          code: ERROR_CODES.DEVELOPER_ERROR,
          message: ex.message,
        });
      }
      return null;
    }

    this.cancellationSignal = new android.os.CancellationSignal();

/*
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
      // use the androidx backport only below android 6.0, because it's an alpha release
      const cb = new AuthenticationCallbackX(promiseResolve, promiseReject, cipherInEncryptMode, keystoreKeyAlias, data);
*/
      const cb = new AuthenticationCallback(promiseResolve, promiseReject, cipherInEncryptMode, keystoreKeyAlias, data);

      const promptInfo = new BiometricPromptX.PromptInfo.Builder()
        .setTitle(dialogText.title)
        // .setSubtitle(dialogText.subtitle)
        // .setDescription(dialogText.description)
        // .setNegativeButtonText(dialogText.negativeButton)
        .setDeviceCredentialAllowed(true)
        .build();
      const prompt = new BiometricPromptX(application.android.foregroundActivity as androidx.appcompat.app.AppCompatActivity, ad.getApplicationContext().getMainExecutor(), cb);

      this.cancellationSignal = new android.os.CancellationSignal();
      this.cancellationSignal.setOnCancelListener(new android.os.CancellationSignal.OnCancelListener({
        onCancel(): void {
          prompt.cancelAuthentication();
        }
      }));
      prompt.authenticate(promptInfo, new BiometricPromptX.CryptoObject(cipher));
/*
    } else {
      // use the new android implementation if available
      const cb = new AuthenticationCallback(promiseResolve, promiseReject, cipherInEncryptMode, keystoreKeyAlias, data);

      const listener = new OnClickListener({
        onClick(): void {
          promiseReject({
            code: ERROR_CODES.CANCEL,
            message: "Auuthentication cancelled by user"
          });
        }
      });

      const prompt = new BiometricPrompt.Builder(ad.getApplicationContext())
        .setTitle(dialogText.title)
        // .setSubtitle(dialogText.subtitle)
        // .setDescription(dialogText.description)
        .setNegativeButton(dialogText.negativeButton, ad.getApplicationContext().getMainExecutor(), listener)
        .build();
      prompt.authenticate(new BiometricPrompt.CryptoObject(cipher), this.cancellationSignal, ad.getApplicationContext().getMainExecutor(), cb);
    }
*/
  }

  private stopListening() {
    if (this.cancellationSignal != null) {
      this.cancellationSignal.cancel();
      this.cancellationSignal = null;
    }
  }
}


class EncryptionUtils {
  public static createKey(keystoreKeyAlias: string): SecretKey {
    const keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");

    const purposes = KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT;
    const keyGenParameterSpec = new KeyGenParameterSpec.Builder(keystoreKeyAlias, purposes)
      .setBlockModes([KeyProperties.BLOCK_MODE_CBC])
      .setEncryptionPaddings([KeyProperties.ENCRYPTION_PADDING_PKCS7])
      .setUserAuthenticationRequired(true)
      .setKeySize(256)
      .build();

    keyGenerator.init(keyGenParameterSpec);
    return keyGenerator.generateKey();
  }

  public static initCipher(mode: number, keystoreKeyAlias: string): Cipher {
    const keyStore = java.security.KeyStore.getInstance("AndroidKeyStore");
    keyStore.load(null);
    const key = keyStore.getKey(keystoreKeyAlias, null);

    if (key == null) {
      throw new Error("Key not found while decrypting.");
    }
    const cipher = Cipher.getInstance(`${KeyProperties.KEY_ALGORITHM_AES}/${KeyProperties.BLOCK_MODE_CBC}/${KeyProperties.ENCRYPTION_PADDING_PKCS7}`);
    if (mode === Cipher.ENCRYPT_MODE) {
      cipher.init(Cipher.ENCRYPT_MODE, key);
    } else {
      const preferences = PreferenceManager.getDefaultSharedPreferences(ad.getApplicationContext());
      const ivString = preferences.getString(KeystoreAccess.name + keystoreKeyAlias + "_encryption_iv", null);
      if (ivString != null) {
        const encryptionIv = EncryptionUtils.base64Decode(ivString);
        cipher.init(Cipher.DECRYPT_MODE, key, new javax.crypto.spec.IvParameterSpec(encryptionIv));
      } else {
        throw new Error("IV not found while decrypting.");
      }
    }
    return cipher;
  }

  public static encrypt(secret: string, keystoreKeyAlias: string, cipher: Cipher): void {
    const encrypted = EncryptionUtils.base64Encode(cipher.doFinal(new java.lang.String(secret).getBytes("UTF-8")));
    const preferences = PreferenceManager.getDefaultSharedPreferences(ad.getApplicationContext());
    // Store IV alongside encrypted data because we need it for decryption. IV makes it harder to decipher the  for a hacker with access to the device data
    const ivString = EncryptionUtils.base64Encode(cipher.getIV());
    preferences.edit()
      .putString(KeystoreAccess.name + keystoreKeyAlias, encrypted)
      .putString(KeystoreAccess.name + keystoreKeyAlias + "_encryption_iv", ivString).apply();
  }

  public static decrypt(keystoreKeyAlias: string, cipher: Cipher): string {
    const preferences = android.preference.PreferenceManager.getDefaultSharedPreferences(ad.getApplicationContext());
    const secret = EncryptionUtils.base64Decode(preferences.getString(KeystoreAccess.name + keystoreKeyAlias, ""));
    const decrypted = cipher.doFinal(secret);
    return new java.lang.String(decrypted, "UTF-8").toString();
  }

  public static base64Encode(value: native.Array<number>): string {
    return new java.lang.String(Base64.encode(value, Base64.DEFAULT), "UTF-8").toString();
  }

  public static base64Decode(value: string): native.Array<number> {
    const javaString = new java.lang.String(new java.lang.StringBuffer(value));
    return Base64.decode(javaString.getBytes("UTF-8"), Base64.DEFAULT);
  }


}

/*
class AuthenticationCallback extends BiometricPrompt.AuthenticationCallback {
  public constructor(
    private _promiseResolve: (value?: string | PromiseLike<string>) => void,
    private _promiseReject: (reason?: any) => void,
    private _cipherInEncryptMode: boolean,
    private _keystoreKeyAlias: string,
    private _data?: string
  ) {
    super();
  }

  public onAuthenticationError(errorCode: number, errString: string): void {
    this._promiseReject({
      code: ERROR_CODES.AUTHENTICATION_FAILED,
      message: errString,
      errorCode: errorCode
    });
  }

  public onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult | BiometricPromptX.AuthenticationResult) {
    try {
      if (this._cipherInEncryptMode) {
        EncryptionUtils.encrypt(this._data, this._keystoreKeyAlias, result.getCryptoObject().getCipher());
        this._promiseResolve();
      } else {
        const decrypted = EncryptionUtils.decrypt(this._keystoreKeyAlias, result.getCryptoObject().getCipher());
        this._promiseResolve(decrypted);
      }
    } catch (ex) {
      this._promiseReject({
        code: ERROR_CODES.DEVELOPER_ERROR,
        message: ex.message
      });
    }
  }
}

class AuthenticationCallbackX extends BiometricPromptX.AuthenticationCallback {
  private _callback: AuthenticationCallback;

  public constructor(
    promiseResolve: (value?: string | PromiseLike<string>) => void,
    promiseReject: (reason?: any) => void,
    cipherInEncryptMode: boolean,
    keystoreKeyAlias: string,
    data?: string
  ) {
    super();
    this._callback = new AuthenticationCallback(promiseResolve, promiseReject, cipherInEncryptMode, keystoreKeyAlias, data);
  }

  public onAuthenticationError(errorCode: number, errString: string): void {
    this._callback.onAuthenticationError(errorCode, errString);
  }

  public onAuthenticationSucceeded(result: BiometricPromptX.AuthenticationResult) {
    this._callback.onAuthenticationSucceeded(result);
  }
}
*/

class AuthenticationCallback extends BiometricPromptX.AuthenticationCallback {
  public constructor(
    private _promiseResolve: (value?: string | PromiseLike<string>) => void,
    private _promiseReject: (reason?: any) => void,
    private _cipherInEncryptMode: boolean,
    private _keystoreKeyAlias: string,
    private _data?: string
  ) {
    super();
  }

  public onAuthenticationError(errorCode: number, errString: string): void {
    this._promiseReject({
      code: ERROR_CODES.AUTHENTICATION_FAILED,
      message: errString,
      errorCode: errorCode
    });
  }

  public onAuthenticationSucceeded(result: BiometricPromptX.AuthenticationResult) {
    try {
      if (this._cipherInEncryptMode) {
        EncryptionUtils.encrypt(this._data, this._keystoreKeyAlias, result.getCryptoObject().getCipher());
        this._promiseResolve();
      } else {
        const decrypted = EncryptionUtils.decrypt(this._keystoreKeyAlias, result.getCryptoObject().getCipher());
        this._promiseResolve(decrypted);
      }
    } catch (ex) {
      this._promiseReject({
        code: ERROR_CODES.DEVELOPER_ERROR,
        message: ex.message
      });
    }
  }
}
