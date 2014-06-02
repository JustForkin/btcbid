
var CURVE_SIZE = 32;    // Bytes
var CURVE = 'secp256k1';
var VERSION = Bitcoin.networks.testnet;
var SATOSHI_PER_BTC = 100000000;

var pubkey_hex = '03720b09514e34c7d7cb5f7b83fbf01f42f4aad4d8848a612d0cfffa8412ae2e91';

// pubkey_hex is a bitcoin pubkey in hex
// price and quantity are integers between 0 and 2*32-1
function encrypt_bid(pubkey, price, quantity)
{
    // Message consists of hex price (8 bytes), quantity (4 bytes), padding (12 bytes)
    msg = ("0000000000000000" + price.toString(16)).slice(-16)
    msg += ("00000000" + (quantity>>>0).toString(16)).slice(-8)
    msg += "000000000000000000000000"   // Padding, could be randomized (don't think this is needed though?)

    console.log('Encoding message ' + msg);

    // Convert msg into Fp
    m = BigInteger.fromHex(msg)         // BigInteger

    // generate random k in F_p
    var k_arr = new Uint8Array(CURVE_SIZE);
    window.crypto.getRandomValues(k_arr);
    // HACK: BigInteger expects a DER encoded string and
    // fromByteArrayUnsigned's wrapper doesn't handle TypedArrays correctly
    if (k_arr[0] & 0x80) {
        var k_arr_hack = new Uint8Array(CURVE_SIZE+1);
        k_arr_hack[0] = 0;
        for (i=0; i<CURVE_SIZE; i++)
            k_arr_hack[i+1] = k_arr[i];
        k_arr = k_arr_hack;
    }
    k = BigInteger.fromByteArrayUnsigned(k_arr);

    // This is the curve we'll use
    ecparam = Bitcoin.sec(CURVE)

    // Calculate C = kP
    var C = ecparam.getG().multiply(k)    // ECPointFp

    // calculate c = x_coord(kY) = x_coord(kxP)
    var kxP = pubkey.Q.multiply(k)
    var c = kxP.getX().toBigInteger()    // BigInteger

    // d = c*m mod q
    var d = c.multiply(m).mod(ecparam.getCurve().getQ())    // BigInteger

    return [BigInteger.fromDERInteger(C.getEncoded(1)).toHex(), d.toHex()]
}

function hex2arr(str)
{
    var arr = [];
    for (i=0; i<str.length; i+=2) {
        arr.push(parseInt(str.substr(i, 2), 16))
    }
    return Buffer.Buffer(arr);
}

function decrypt_bid(key, C_hex, d_hex)
{
    ecparam = Bitcoin.sec(CURVE)

    // Convert from hex to ECPointFp and BigInteger
    C = Bitcoin.ECPointFp.decodeFrom(ecparam.getCurve(), hex2arr(C_hex)).Q
    d = BigInteger.fromHex(d_hex);

    // calculate c' = x_coord(xC)
    x = key.D
    c1 = C.multiply(x)
    c = c1.getX().toBigInteger()

    // m = d/c' mod q
    q = ecparam.getCurve().getQ()
    m = d.multiply(c.modInverse(q)).mod(q)

    return m.toHex()
}

function go() {

    key = Bitcoin.ECKey.makeRandom()

    console.log('-----------------------------------------------')
    console.log('Warning: do NOT use this as a bitcoin address')
    console.log('Market Maker Private key: ' + key.toWIF(VERSION.wif))
    console.log('Market Maker Public key:  ' + key.pub.toHex())
    console.log('-----------------------------------------------')


    // E_MM(price, quantity, salt) -> C, d

    // Alice 10 BTC -> MarketMaker
    //              -> OP_RETURN C
    //              -> OP_RETURN d

    var enc = encrypt_bid(key.pub.toHex(), 615, 1);

    console.log('Encrypted to (C, d): ' + enc[0] + ', ' + enc[1])


    // Now decrypt it
    dec = decrypt_bid(key, enc[0], enc[1])

    console.log('Decrypted to ' + dec);

}

function parse_unspent(satoshi_needed)
{
    utxo = JSON.parse($('#unspent')[0].value)
    satoshi_found = 0;  // TODO: have a smarter algorithm that tries to minimize inputs
                        // or change?
    inputs = []
    for (i=0; i<utxo.length; i++) {
        tx = utxo[i]

        inputs.push(tx);
        satoshi_found += tx.amount * SATOSHI_PER_BTC;

        if (satoshi_found >= satoshi_needed) {
            $('#unspent-error').hide()
            return inputs;
        }
    }

    $('#unspent-total')[0].innerHTML = (satoshi_found / SATOSHI_PER_BTC);
    $('#unspent-error').show()
    return false;
}

function create_transaction(inputs, pubkey, data, needed)
{

    tx = new Bitcoin.Transaction()
    var change_addr
    var provided = 0

    for (i=0; i<inputs.length; i++) {
        if (inputs[i].address != undefined && change_addr == undefined) {
            change_addr = inputs[i].address;    // HACK, change goes to first address
        }

        sin = Bitcoin.Script.fromHex(inputs[i].scriptPubKey)
        txin = new Bitcoin.TransactionIn({ hash: inputs[i].txid, index: inputs[i].vout, script: sin })
        tx.addInput(txin);
        provided += inputs[i].amount * SATOSHI_PER_BTC
    }


    // Ouput 0: coins to market maker
    // TODO: make this address setable; not the above key
    //sout0 = new Bitcoin.Script.createPubKeyHashScriptPubKey(
    sout0 = pubkey.getAddress(VERSION.pubKeyHash).toScriptPubKey()
    txout0 = new Bitcoin.TransactionOut({script: sout0, value: needed})

    // Encode C in an OP_RETURN <data>
    sout1 = new Bitcoin.Script()
    sout1.writeOp(Bitcoin.opcodes.OP_RETURN)
    sout1.writeBytes(Buffer.Buffer(data[0], "hex"))
    txout1 = new Bitcoin.TransactionOut({script: sout1, value: 1})

    // Encode d in an OP_RETURN <data>
    sout2 = new Bitcoin.Script()
    sout2.writeOp(Bitcoin.opcodes.OP_RETURN)
    sout2.writeBytes(Buffer.Buffer(data[1], "hex"))
    txout2 = new Bitcoin.TransactionOut({script: sout2, value: 1})

    // Change address
    fee = 0 // Wheeeeee
    sout3 = Bitcoin.Address.fromBase58Check(change_addr).toScriptPubKey()
    txout3 = new Bitcoin.TransactionOut({script: sout3, value: (provided - needed - 2 - fee)})

    tx.addOutput(txout0)
    tx.addOutput(txout1)
    tx.addOutput(txout2)
    tx.addOutput(txout3)

    console.log('Please sign this tx: ' + tx.toHex())
    $('#txout')[0].innerHTML = tx.toHex()
}

function update_bid()
{
    price = $('#price')[0].value
    quantity = $('#quantity')[0].value

    needed = price * SATOSHI_PER_BTC * quantity

    $('#required')[0].innerHTML = needed / SATOSHI_PER_BTC;

    txs = parse_unspent(needed);
    if (txs === false) {
        $('#txout')[0].innerHTML = '';
        return
    }


    // Get pubkey from hex
    pubkey = Bitcoin.ECPubKey.fromHex(pubkey_hex)

    enc_data = encrypt_bid(pubkey, price*SATOSHI_PER_BTC, quantity)

    if (needed < 1) {
        needed = 1
    }
    create_transaction(txs, pubkey, enc_data, needed)
}

//window.onload=go;



