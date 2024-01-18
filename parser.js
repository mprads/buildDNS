const fs = require('fs');
const readLine = require('readline');

module.exports = processBindFile;

async function processBindFile(filePath='zones/example2.com.zone') {
    let origin;
    let ttl;
    let previousTtl;
    let previousName;
    let records = [];
    let soa = {};
    let soaLine = 0;
    let multiLineSoa = false;
    let containsTtl = false;

    let recordsType = ['SOA', 'NS', 'A', 'CNAME', 'MX'];
        recordsType.forEach(element => {
        records[element] = [];
    });

    const fileStream = fs.createReadStream(filePath);
    // Create stream to access file contents asynchronously
    const rl = readLine.createInterface({ input: fileStream, crlfDelay: Infinity });

    for await (const line of rl) {
        if (line.length > 1) {
            let l = line.trim().replace(/\t/g, ' ').replace(/\s+/g, ' ');
            let commentedLine = false;
            let commentIndex = l.indexOf(';');

            // If the comment is anywhere but the begining split the line and ignore the commented part
            if (commentIndex != -1) {
                if (commentIndex != 0) {
                    let content = l.split(';');
                    l = content[0];
                } else {
                    commentedLine = true;
                };
            };

            if (!commentedLine) {
                let splitLine = l.split(' ');
                switch (splitLine[0]) {
                    case '$ORIGIN':
                        origin = splitLine[1];
                        break;
                    
                    case '$TTL':
                        ttl = splitLine[1];
                        break;

                    case '$INCLUDE':
                        break;
                    
                    default:
                        // Checking if the state of authority is single line or multi line and storing all its content
                        if (splitLine.includes('SOA')) {
                            previousName = splitLine[0];
                            soa.mname = splitLine[3];
                            soa.rname = splitLine[4];

                            if (splitLine.includes(')')) {
                                soa.serial = splitLine[6]; 
                                soa.refresh = splitLine[7];
                                soa.retry = splitLine[8];
                                soa.expire = splitLine[9];
                                soa.title = splitLine[10];
                            } else {
                                multiLineSoa = true;
                                soaLine++;
                            };
                        };

                        recordsType.forEach(element => {
                            if (splitLine.includes(element)) {
                                type = element;

                                if (type != 'SOA') {
                                    let rr;

                                    [rr, previousName, previousTtl] = processRr(splitLine, containsTtl, previousTtl, previousName, origin, ttl);

                                    records[type].push(rr);
                                };
                            };
                        });
                        break;
                };

                if (multiLineSoa) {
                    switch (soaLine) {
                        case 2:
                            soa.serial = splitLine[0];
                            break;
                        
                        case 3:
                            soa.refresh = splitLine[0];
                            break;
                        
                        case 4:
                            soa.retry = splitLine[0];
                            break;

                        case 5:
                            soa.expire = splitLine[0];
                            break;

                        case 6:
                            soa.minimum = splitLine[0];
                            break;

                        default:
                            break;
                    };
                };

                // closing bracket of multi line soa, push the complete soa to records and flip multiline to false
                if (splitLine.includes(')')) {
                    records['SOA'].push(soa);
                    multiLineSoa = false;
                }

                soaLine++
            };
        };
    };
};

function  processRr(splitLine, containsTtl, previousTtl, previousName, origin, ttl) {
    let rr = {};
    let totalLength = splitLine.length;
    // If the second to last item of the record is a int, the record is a MX
    let isMx = Number(splitLine[totalLength - 2]);

    switch (totalLength) {
        case 5:
            for (let index = 0; index < totalLength; index++) {
                const element = splitLine[index];

                // Ignore ip addressess
                if (!element.includes('.')) {
                    if (parseInt(element)) {
                        if (!isMx) {
                            containsTtl = true;
                            previousTtl = element;
                            splitLine.splice(index, 1);
                        };
                        
                        break;
                    };
                };
            };

            if (!isMx) {
                previousName = splitLine[0];
                rr.class = splitLine[1];
                rr.type = splitLine[2];
                rr.data = splitLine[3];
            };

            break;
        
        // Only 4 items in record means the name or ttl is missing
        case 4:
            for (let index = 0; index < totalLength; index++) {
                const element = splitLine[index];
                // Ignore ip addressess
                if (!element.includes('.')) {
                    // Make sure second last index is not an int and therefore not a MX
                    if (parseInt(element)) {
                        if (!isMx) {  
                            containsTtl = true;
                            previousTtl = element;
                            splitLine.splice(index, 1);
                        };

                        break;
                    };
                } ;
            };
            
            //Name is missing
            if (containsTtl) { 
                rr.class = splitLine[0];
                rr.type = splitLine[1];
                rr.data = splitLine[2]; 

            } else {
                if(isMx){
                    previousName = "@";
                    rr.class = splitLine[0];
                    rr.type = splitLine[1];
                    rr.preference = splitLine[2];
                    rr.data = splitLine[3];
                
                } else {
                    previousName = splitLine[0];
                    rr.class = splitLine[1];
                    rr.type = splitLine[2];
                    rr.data = splitLine[3];
                };
            };
            
            break;

        case 3:
            rr.class = splitLine[0];
            rr.type = splitLine[1];
            rr.data = splitLine[2];
            
            break;

        case 2:
            break; 

        default:
            break;
    };
    rr.name = previousName || origin;
    rr.ttl =  previousTtl || ttl;

    return [rr, previousName, previousTtl];
};