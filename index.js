const dgram = require('dgram');
const processBindFile = require('./parser.js');

const server = dgram.createSocket('udp4');

server.bind(53);

// A byte is 8 bits
// First two bytes are transaction id which is sent back
// Second two bytes are flags
// Next 4 are the OPCODE that tell us what type of query it is, which is passed back in the response
// Next bit defines if the DNS packet carries a response
// Next bit is for when the message exceeds the limit
// Next two bits are directed to a named server for recursive query
// Zero save for future uses
// 4 bits that are the return of the OPCODE
// Two bytes integer specifying the number of entries in question section
// Two byte integer specifying the number of resource records in answer section
// Two byte integer specifying number of name server records in authority sectoin
// Two byte integer

server.on('message', async(msg, rinfo) => {
    let recordsResult;
    let qt;
    let domainParts;
    let askedRecord;
    let TID = msg.slice(0,2);
    let FLAGS = getFlags(msg.slice(2, 4));

    FLAGS = new Buffer.from(parseInt(FLAGS, 2).toString(16), 'hex');

    [recordsResult, qt, domainParts, askedRecord] = await getRecords(msg.slice(12))

    let askedRecords = recordsResult[qt].filter(element => element.name == askedRecord);
    let ANCOUNT = askedRecords.length.toString(16).padStart(4, 0);

    ANCOUNT = new Buffer.from(ANCOUNT, 'hex');

    // For simplicity assuming there is only one question in the DNS theory
    let QDCOUNT = new Buffer.from('0001', 'hex');

    // Not needed for basic implementation
    let NSCOUNT = new Buffer.from('0000', 'hex');
    let ARCOUNT = new Buffer.from('0000', 'hex');

    let domainQuestion = new Buffer.from(buildQuestion(domainParts, qt), 'hex');
    
    let dnsBody = '';

    for (let record of askedRecords) {
        dnsBody += recordToBytes(qt, record); 
    }

    dnsBody = new Buffer.from(dnsBody, 'hex');


    server.send([TID,FLAGS, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT, domainQuestion, dnsBody], rinfo.port)
});


function getFlags(flags) {
    // DNS packet is carrying a response
    let QR = '1';

    let byte1 = flags.slice(0,1);
    let OPCode = bitsExtract(byte1);
    let AA = '1';
    let TC = '0';
    let RD = '0';
    
    // Byte 2
    let RA = '0';
    let Z = '000';
    let RCODE = '0000';

    let header1 = QR + OPCode + AA + TC + RD;
    let header2 = RA + Z + RCODE;
    
    return header1 + header2;
};


function bitsExtract(data) {
    let opcode = '';

    for (let bit = 1; bit < 5; bit++) {
        opcode += ((data.toString().charCodeAt())&(1<<bit)).toString();
    };

    return opcode;
};

async function getRecords(data){
    let result = getDomain(data);
    let domain = result[0];
    let domainName;
    let askedRecord = '@';

    if (domain.length > 2) {
        askedRecord = result[0][0];
        domainName = result[0][1] + '.' + result[0][2]
    } else {
        domainName = result[0].join('.');
    };
    
    let qt = getRecordType(result[1])
    let filePath = `zones/${domainName}.zone`;
    let records = await processBindFile(filePath);
    
    return [records, qt, result[0], askedRecord]
};

function getDomain(data) {
    let state = 0;
    let expectedLength = 0;
    let domainString = '';
    let domainParts = [];
    let x = 0;
    // number of bytes examined
    let y = 0;

    for (let pair of data.entries()) {
        if (state == 1) {
            domainString += String.fromCharCode(pair[1]);
            x++;
            if (x == expectedLength) {
                domainParts.push(domainString);
                domainString = '';
                state = 0;
                x = 0;
            }
            // Break if pair are 00 which is the terminator of the byte
            if (pair[1] == 0) {
                break;
            }
        } else {
            state = 1;
            expectedLength = pair[1];
        };

        y++;
    };

    let recordType = data.slice(y, y+2);

    return [domainParts, recordType];
};

function buildQuestion(domainParts, recordType) {
    let qBytes = '';

    for (let part of domainParts) {
        let length = part.length;
        qBytes += length.toString(16).padStart(2, 0);

        for (let char of part) {
            qBytes += char.charCodeAt(0).toString(16);
        };
    };

    qBytes += '00';
    qBytes += getRecordTypeHex(recordType)
    // 0001 indicated end of question section
    qBytes +=  '00' + '01';

    return qBytes;
};

function recordToBytes( recordType, record) {
    // Indicates where the client should start looking for the record
    let rBytes = 'c00c';

    rBytes += getRecordTypeHex(recordType);
    rBytes +=  '00' + '01';
    rBytes +=  parseInt(record["ttl"]).toString(16).padStart(8, 0);

    let alphabetDomain = '';

    if (recordType == 'A') {
        // Length is always 4 as we are returing an IPV4 address of length 4
        rBytes +=  '00' + '04'; 

        // Indivual numbers from IP address are converted to hex and adjusted for length
        for (let part of record["data"].split('.')) {
            rBytes += parseInt(part).toString(16).padStart(2, 0);
        };
    } else if (recordType == 'SOA') {
        let mname = domainToHex(record["mname"]);
        let rname = domainToHex(record["rname"])
        let serial = stringToHex(record["serial"]);
        let refresh = stringToHex(record["refresh"]);
        let retry = stringToHex(record["retry"]);
        let expire = stringToHex(record["expire"])
        let minimum = stringToHex(record["minimum"]);

        alphabetDomain += mname + rname + serial + refresh + retry + expire + minimum;

    } else {        
        alphabetDomain = domainToHex(record["data"]);
    };
    
    if (alphabetDomain != ''){

        
        switch (recordType) {
            case 'CNAME':
                alphabetDomain += '00';     
                break;
            case 'MX':
                alphabetDomain = parseInt(record["preference"]).toString(16).padStart(4, 0) + alphabetDomain;
                break;
        
            default:
                break;
        }
        let totalLength = (alphabetDomain.length / 2).toString(16).padStart(4, 0);
        rBytes += totalLength + alphabetDomain;
    }
    
    return rBytes;
}

function domainToHex(domain) {
    let alphabetDomain = '';
    let alphabetDomainLength = 0;
    let bytes;

    for (const word of domain.split('.')) {
        bytes = '';

        for (const char of word) {
            bytes += char.charCodeAt().toString(16).padStart(2, 0)
        }

        alphabetDomainLength = (bytes.length / 2).toString(16).padStart(2, 0);
        alphabetDomain += alphabetDomainLength + bytes;
    };

    return alphabetDomain;
};

function stringToHex(string){
    return parseInt(string).toString(16).padStart(8, 0);
};