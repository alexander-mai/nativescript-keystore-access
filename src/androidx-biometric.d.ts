/// <reference path="android-declarations.d.ts"/>

declare module androidx {
  export module biometric {
    export class BiometricConstants {
      public static class: java.lang.Class<androidx.biometric.BiometricConstants>;
      /**
       * Constructs a new instance of the androidx.biometric.BiometricConstants interface with the provided implementation. An empty constructor exists calling super() when extending the interface class.
       */
      public constructor(implementation: {
      });
      public constructor();
      public static ERROR_UNABLE_TO_REMOVE: number;
      public static ERROR_VENDOR_BASE: number;
      public static ERROR_HW_UNAVAILABLE: number;
      public static ERROR_NO_DEVICE_CREDENTIAL: number;
      public static ERROR_CANCELED: number;
      public static ERROR_LOCKOUT_PERMANENT: number;
      public static ERROR_UNABLE_TO_PROCESS: number;
      public static ERROR_NO_BIOMETRICS: number;
      public static ERROR_NO_SPACE: number;
      public static ERROR_NEGATIVE_BUTTON: number;
      public static ERROR_TIMEOUT: number;
      public static ERROR_LOCKOUT: number;
      public static ERROR_USER_CANCELED: number;
      public static ERROR_HW_NOT_PRESENT: number;
      public static ERROR_VENDOR: number;
    }
  }
}

declare module androidx {
  export module biometric {
    export class BiometricFragment {
      public static class: java.lang.Class<androidx.biometric.BiometricFragment>;
      public getNegativeButtonText(): string;
      public onCreate(param0: globalAndroid.os.Bundle): void;
      public constructor();
      public onAttach(param0: globalAndroid.content.Context): void;
      public onCreateView(param0: globalAndroid.view.LayoutInflater, param1: globalAndroid.view.ViewGroup, param2: globalAndroid.os.Bundle): globalAndroid.view.View;
    }
  }
}

declare module androidx {
  export module biometric {
    export class BiometricManager {
      public static class: java.lang.Class<androidx.biometric.BiometricManager>;
      public static BIOMETRIC_SUCCESS: number;
      public static BIOMETRIC_ERROR_HW_UNAVAILABLE: number;
      public static BIOMETRIC_ERROR_NONE_ENROLLED: number;
      public static BIOMETRIC_ERROR_NO_HARDWARE: number;
      public canAuthenticate(): number;
      public static from(param0: globalAndroid.content.Context): androidx.biometric.BiometricManager;
    }
    export module BiometricManager {
      export class Api29Impl {
        public static class: java.lang.Class<androidx.biometric.BiometricManager.Api29Impl>;
      }
    }
  }
}

declare module androidx {
  export module biometric {
    export class BiometricPrompt extends androidx.biometric.BiometricConstants {
      public static class: java.lang.Class<androidx.biometric.BiometricPrompt>;
      public authenticate(param0: androidx.biometric.BiometricPrompt.PromptInfo, param1: androidx.biometric.BiometricPrompt.CryptoObject): void;
      public constructor(param0: androidx.fragment.app.Fragment, param1: java.util.concurrent.Executor, param2: androidx.biometric.BiometricPrompt.AuthenticationCallback);
      public authenticate(param0: androidx.biometric.BiometricPrompt.PromptInfo): void;
      public constructor(param0: androidx.fragment.app.FragmentActivity, param1: java.util.concurrent.Executor, param2: androidx.biometric.BiometricPrompt.AuthenticationCallback);
      public cancelAuthentication(): void;
    }
    export module BiometricPrompt {
      export abstract class AuthenticationCallback {
        public static class: java.lang.Class<androidx.biometric.BiometricPrompt.AuthenticationCallback>;
        public onAuthenticationFailed(): void;
        public onAuthenticationError(param0: number, param1: string): void;
        public onAuthenticationSucceeded(param0: androidx.biometric.BiometricPrompt.AuthenticationResult): void;
        public constructor();
      }
      export class AuthenticationResult {
        public static class: java.lang.Class<androidx.biometric.BiometricPrompt.AuthenticationResult>;
        public getCryptoObject(): androidx.biometric.BiometricPrompt.CryptoObject;
      }
      export class CryptoObject {
        public static class: java.lang.Class<androidx.biometric.BiometricPrompt.CryptoObject>;
        public constructor(param0: java.security.Signature);
        public getSignature(): java.security.Signature;
        public getMac(): javax.crypto.Mac;
        public constructor(param0: javax.crypto.Cipher);
        public getCipher(): javax.crypto.Cipher;
        public constructor(param0: javax.crypto.Mac);
      }
      export class PromptInfo {
        public static class: java.lang.Class<androidx.biometric.BiometricPrompt.PromptInfo>;
        public getNegativeButtonText(): string;
        public isConfirmationRequired(): boolean;
        public getSubtitle(): string;
        public getDescription(): string;
        public isDeviceCredentialAllowed(): boolean;
        public getTitle(): string;
      }
      export module PromptInfo {
        export class Builder {
          public static class: java.lang.Class<androidx.biometric.BiometricPrompt.PromptInfo.Builder>;
          public setSubtitle(param0: string): androidx.biometric.BiometricPrompt.PromptInfo.Builder;
          public constructor();
          public setDeviceCredentialAllowed(param0: boolean): androidx.biometric.BiometricPrompt.PromptInfo.Builder;
          public setDescription(param0: string): androidx.biometric.BiometricPrompt.PromptInfo.Builder;
          public build(): androidx.biometric.BiometricPrompt.PromptInfo;
          public setTitle(param0: string): androidx.biometric.BiometricPrompt.PromptInfo.Builder;
          public setNegativeButtonText(param0: string): androidx.biometric.BiometricPrompt.PromptInfo.Builder;
          public setConfirmationRequired(param0: boolean): androidx.biometric.BiometricPrompt.PromptInfo.Builder;
        }
      }
    }
  }
}

declare module androidx {
  export module biometric {
    export class DeviceCredentialHandlerActivity {
      public static class: java.lang.Class<androidx.biometric.DeviceCredentialHandlerActivity>;
      public onSaveInstanceState(param0: globalAndroid.os.Bundle): void;
      public onCreate(param0: globalAndroid.os.Bundle): void;
      public onPause(): void;
      public onActivityResult(param0: number, param1: number, param2: globalAndroid.content.Intent): void;
      public constructor();
    }
  }
}

declare module androidx {
  export module biometric {
    export class DeviceCredentialHandlerBridge {
      public static class: java.lang.Class<androidx.biometric.DeviceCredentialHandlerBridge>;
      public getFingerprintDialogFragment(): androidx.biometric.FingerprintDialogFragment;
      public getFingerprintHelperFragment(): androidx.biometric.FingerprintHelperFragment;
    }
  }
}

declare module androidx {
  export module biometric {
    export class FingerprintDialogFragment {
      public static class: java.lang.Class<androidx.biometric.FingerprintDialogFragment>;
      public getNegativeButtonText(): string;
      public onResume(): void;
      public onSaveInstanceState(param0: globalAndroid.os.Bundle): void;
      public onCreateDialog(param0: globalAndroid.os.Bundle): globalAndroid.app.Dialog;
      public onCreate(param0: globalAndroid.os.Bundle): void;
      public onPause(): void;
      public constructor();
      public onCancel(param0: globalAndroid.content.DialogInterface): void;
      public setBundle(param0: globalAndroid.os.Bundle): void;
    }
    export module FingerprintDialogFragment {
      export class H {
        public static class: java.lang.Class<androidx.biometric.FingerprintDialogFragment.H>;
        public handleMessage(param0: globalAndroid.os.Message): void;
      }
    }
  }
}

declare module androidx {
  export module biometric {
    export class FingerprintHelperFragment {
      public static class: java.lang.Class<androidx.biometric.FingerprintHelperFragment>;
      public onCreate(param0: globalAndroid.os.Bundle): void;
      public constructor();
      public onCreateView(param0: globalAndroid.view.LayoutInflater, param1: globalAndroid.view.ViewGroup, param2: globalAndroid.os.Bundle): globalAndroid.view.View;
    }
    export module FingerprintHelperFragment {
      export class MessageRouter {
        public static class: java.lang.Class<androidx.biometric.FingerprintHelperFragment.MessageRouter>;
      }
    }
  }
}

declare module androidx {
  export module biometric {
    export class Utils {
      public static class: java.lang.Class<androidx.biometric.Utils>;
    }
  }
}

//Generics information:

