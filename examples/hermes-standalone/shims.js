// Minimal shims to run the SDK on the standalone Hermes CLI.
//
// In a real React Native app these globals are NOT shimmed like this:
// - crypto.getRandomValues is provided by `react-native-get-random-values`
//   (native OS entropy via SecRandomCopyBytes/SecureRandom). That polyfill
//   needs the RN runtime (NativeModules), so only its surface is replicated
//   here. Math.random is NOT cryptographically secure: this shim exists
//   solely to validate the engine.
// - console exists in RN; the Hermes CLI only ships print().

if (typeof globalThis.console === 'undefined') {
  globalThis.console = {
    log: (...args) => print(args.join(' ')),
    error: (...args) => print('ERROR: ' + args.join(' ')),
  };
}

if (typeof globalThis.crypto === 'undefined') {
  globalThis.crypto = {
    getRandomValues(array) {
      for (let i = 0; i < array.length; i++) {
        array[i] = Math.floor(Math.random() * 256);
      }
      return array;
    },
  };
}
