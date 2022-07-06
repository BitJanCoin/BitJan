const express = require('express')
const app = express()
const ejs = require('ejs');
const crypto = require('crypto')
const secp256k1 = require('secp256k1')
const cookieParser = require('cookie-parser');

app.use(express.static('static'))
app.engine('.ejs', ejs.__express);
app.set('views',__dirname+'/views');
app.use(cookieParser());

app.get('/', (req, res) => {
	res.render('./index.ejs', {
		privkey: crypto.createHash('sha256').update(crypto.randomBytes(64)).digest("hex")
	});
})
app.get('/wallet', (req, res) => {
	if(req.cookies.privkey){
		res.render('./wallet.ejs', {
			pubkey: crypto.createHash('sha256').update(secp256k1.publicKeyCreate(crypto.createHash('sha256').update(req.cookies.privkey).digest())).digest("hex")
		});
	}else{
		res.redirect("/");
	}
})

app.listen(80, () => {
  console.log('Node Started')
})

const msg = crypto.createHash('sha256').update('s').digest()

// generate privKey
let privKey
do {
  privKey = crypto.randomBytes(32)
} while (!secp256k1.privateKeyVerify(privKey))

// get the public key in a compressed format
const pubKey = secp256k1.publicKeyCreate(privKey)

// sign the message
const sigObj = secp256k1.ecdsaSign(msg, privKey)

// verify the signature
console.log(secp256k1.ecdsaVerify(sigObj.signature, msg, pubKey))

console.log(crypto.createHash('sha256').update(crypto.randomBytes(64)).digest("hex"));
console.log(pubKey);