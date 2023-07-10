//const BigInteger = require('big-integer');
//const readline = require('readline-sync');
const p_field = document.getElementById('p');
const q_field = document.getElementById('q');
const e_field = document.getElementById('e');

let plainText;
let cipherText;
    
class RSA{
  static p;
  static q;
  static n;
  static phi;
  static encryptionPublicKey;
  static decryptionPrivateKey;
  static validValues = new Set();
  
  static get P(){
    return RSA.p;
  }
  static get Q(){
    return RSA.q;
  }
  static get N(){
    return RSA.n;
  }
  static get Phi(){
    return RSA.phi; 
  }
  static get encryptionKey(){
    return RSA.encryptionPublicKey;
  }
  static get decryptionKey(){
    return RSA.decryptionPrivateKey;
  }


  static set P(value){
    if(isNaN(value)){
      throw new Error("Please enter a valid p value!");
    }
    RSA.p = BigInt(value.toString());
  }
  static set Q(value){
    if(isNaN(value)){
      throw new Error("Please enter a valid q value!");
    }
    RSA.q = BigInt(value.toString());
  }
  static set N(value = null){
    RSA.n = RSA.P * RSA.Q;
  }
  static set Phi(phi=null){
    if(!RSA.P || !RSA.Q){
      throw new Error("Please enter p, and q values first!");
    }
    if(RSA.isPrime(RSA.N)){
      RSA.phi = RSA.N - 1n;
      return true;
    }
    const gcdVal = RSA.gcd(RSA.P, RSA.Q);
    if(gcdVal === 1n){
      if(RSA.P === RSA.Q){
        RSA.phi = RSA.P * RSA.Q;
        return true;
      }
      else{
        RSA.phi = (RSA.P-1n) * RSA.Q;
        return true;
      }
    }
  }
  static set encryptionKey(value){
    if(!RSA.validValues.has(BigInt(value))){
      throw new Error("Please enter a valid number for an encryption key!");
    }
    RSA.encryptionPublicKey = BigInt(value);
  }
  static set decryptionKey(value=null){
    if(!RSA.encryptionKey){
      throw new Error("Please enter a valid number for an encryption key first to generate a decryption key for it!");
    }
    RSA.decryptionPrivateKey = BigInt(RSA.modInverse(RSA.encryptionKey, RSA.Phi));
  }

  
  static encrypt = (plainText, encryptionKey = null)=> {
    if(encryptionKey && !RSA.encryptionKey){
      RSA.encryptionKey = encryptionKey;
    }
    let cipherText=[];
    let i=0;
    while(i< plainText.length){
      let decryptionOfChar = (BigInt(plainText.charCodeAt(i++)) ** RSA.encryptionKey) % RSA.N;
      cipherText.push(decryptionOfChar);
    }
     return cipherText;
  };

  static decrypt= (cipherText, encryptionKey)=> {
    if(encryptionKey && !RSA.encryptionKey){
      RSA.encryptionKey = encryptionKey;
    }
    
    RSA.decryptionKey = 0;
    
    const cipherTextChars = cipherText.split(",");

    let i=0;
    cipherTextChars[i] = cipherTextChars[i].trim();
    if(cipherText[i] === "["){
      cipherTextChars[i] = BigInt(cipherTextChars[i++].substr(1));
    }
    
    while(i<cipherTextChars.length - 1){
      cipherTextChars[i] = BigInt(cipherTextChars[i++].trim());
    }
    
    cipherTextChars[i] = BigInt(cipherTextChars[i].trim());
    if(cipherTextChars[i] === "]"){
      cipherTextChars[i] = BigInt(cipherTextChars[i].substr(1));
    }
   
    i=0;
    let plainText = "";
    while(i< cipherTextChars.length){
      let char = String.fromCharCode( Number((cipherTextChars[i] ** RSA.decryptionKey) % RSA.N));
      plainText += char;
      i++;
    }

    return plainText;
  };


  
  static isPrime = (value)=>{
    let i = BigInt(2);
    while(i< value / 2n){
      if(value % i === BigInt(0)){
        return false;
      }
      i = i + 1n; 
    }
    return true;
  };

  static validEncryptionKeyValues = ()=>{
    if(RSA.P && RSA.Q && RSA.Phi){
      let i = BigInt(2);
      while(i < RSA.Phi){
        const gcdVal = RSA.gcd(i, RSA.Phi);
        if(gcdVal === 1n){
          RSA.validValues.add(i);
        }
        i = i + 1n;
      }
      
      let values = "";
      RSA.validValues.forEach(val=>{
        values+=`${val}, `;
      });
      values = values.trim().substr(0, values.length - 1);
      alert(`Please pick one of these values as an encrption key:\n ${values}`);
      
      return RSA.validValues;
    } 
    throw "First enter p, and q values!";
  };

  static gcd = (x, y)=> {
    if ((typeof x !== 'bigint') || (typeof y !== 'bigint')) 
      return false;
    if(x < 0n){
      x = x * -1n;
    }
    if(y < 0n){
      y = y * -1n;
    }
    /*x = BigInt(Math.abs(x));
    y = BigInt(Math.abs(y));*/
    while(y) {
      let t = y;
      y = x % y;
      x = t;
    }
    return x;
  };

  static modInverse = (a, m)=> {
    // validate inputs
    [a, m] = [Number(a), Number(m)]
    if (Number.isNaN(a) || Number.isNaN(m)) {
      throw new Error("Invalid input!"); // invalid input
    }
    a = (a % m + m) % m
    if (!a || m < 2) {
      throw new Error("Invalid input!"); // invalid input
    }
    // find the gcd
    const s = []
    let b = m
    while(b) {
      [a, b] = [b, a % b]
      s.push({a, b})
    }
    if (a !== 1) {
      throw new Error("Inverse does not exist!"); // inverse does not exists
    }
    // find the inverse
    let x = 1
    let y = 0
    for(let i = s.length - 2; i >= 0; --i) {
      [x, y] = [y,  x - y * Math.floor(s[i].a / s[i].b)]
    }
    return (y % m + m) % m
  };
}

  const InitializePAndQ = ()=>{
    try{
      const pTextField = document.getElementById("pTextField");
      const qTextField = document.getElementById("qTextField");
      const eTextField = document.getElementById("eTextField");
      
      
      RSA.P = pTextField.value.toString();
      
      RSA.Q = qTextField.value.toString();
      RSA.N = 0;
      RSA.Phi = 0;
      RSA.validEncryptionKeyValues();
      eTextField.hidden = false;
      
      document.getElementById("textToEncrypt").hidden = false;
      document.getElementById("encryptBttn").hidden = false;
      document.getElementById("encryptionText").hidden = false;;

      document.getElementById("textToDecrypt").hidden = false;
      document.getElementById("decryptBttn").hidden = false;
      document.getElementById("decryptionText").hidden = false;
    }catch(error){
      if(typeof error === "object"){
        alert(`${error.name}: ${error.message}`);
      }
      else{
        alert(error);
      }
    }
  };

  const encryptText = ()=> {
    try{
      const plaintText = document.getElementById("textToEncrypt").value.toString();
      const cipherText = RSA.encrypt(plaintText, document.getElementById("eTextField").value.toString());
      document.getElementById("encryptionText").value = cipherText;
    }catch(error){
      if(typeof error === "object"){
        alert(`${error.name}: ${error.message}`);
      }
      else{
        alert(error);
      }
    }
  };

  

  const decryptText = ()=> {
    try{
      const cipherText = document.getElementById("textToDecrypt").value.toString();
      const plainText = RSA.decrypt(cipherText, document.getElementById("eTextField").value.toString());
      document.getElementById("decryptionText").value = plainText;      
    }catch(error){
      if(error instanceof Error){
        alert(`${error.name}: ${error.message}`);
      }
      else{
        alert(error);
      }
    }
  };





