// Shims mínimos para correr el SDK en el CLI standalone de Hermes.
//
// En una app React Native real estos globals NO se shimean así:
// - crypto.getRandomValues lo provee `react-native-get-random-values`
//   (entropía nativa del SO vía SecRandomCopyBytes/SecureRandom). Ese
//   polyfill necesita el runtime de RN (NativeModules), así que acá se
//   replica solo su superficie. Math.random NO es criptográficamente
//   seguro: este shim existe únicamente para validar el engine.
// - console existe en RN; el CLI de Hermes solo trae print().

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
