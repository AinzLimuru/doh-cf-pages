const doh = 'https://security.cloudflare-dns.com/dns-query';
const dohjson = 'https://security.cloudflare-dns.com/dns-query';
const contype = 'application/dns-message';
const jstontype = 'application/dns-json';

// 自定义解析记录
const customRecords = {
    'example.com': {
        'A': ['0.0.0.0'],
        'AAAA': ['2606:2800:220:1:248:1893:25c8:1946']
    },
    'custom.example': {
        'A': ['192.168.1.1'],
        'AAAA': ['::1']
    }
};

// 解析 DNS 查询
const parseDnsQuery = (dnsQuery) => {
    // 解析 DNS 查询消息
    const queryBuffer = Buffer.from(dnsQuery, 'base64');
    const transactionId = queryBuffer.slice(0, 2);
    const flags = queryBuffer.slice(2, 4);
    const qdcount = queryBuffer.readUInt16BE(4);
    const ancount = queryBuffer.readUInt16BE(6);
    const nscount = queryBuffer.readUInt16BE(8);
    const arcount = queryBuffer.readUInt16BE(10);

    let offset = 12;
    const questions = [];

    for (let i = 0; i < qdcount; i++) {
        const question = {};
        let qname = '';
        while (true) {
            const length = queryBuffer.readUInt8(offset);
            offset += 1;
            if (length === 0) break;
            qname += queryBuffer.toString('utf8', offset, offset + length) + '.';
            offset += length;
        }
        question.qname = qname.slice(0, -1);
        question.qtype = queryBuffer.readUInt16BE(offset);
        offset += 2;
        question.qclass = queryBuffer.readUInt16BE(offset);
        offset += 2;
        questions.push(question);
    }

    return { transactionId, flags, questions };
};

// 构建自定义 DNS 响应
const buildDnsResponse = (transactionId, flags, questions, answers) => {
    const responseBuffer = Buffer.alloc(512);
    transactionId.copy(responseBuffer, 0, 0, 2);
    flags.copy(responseBuffer, 0, 2, 4);
    responseBuffer.writeUInt16BE(questions.length, 4);
    responseBuffer.writeUInt16BE(answers.length, 6);
    responseBuffer.writeUInt16BE(0, 8);
    responseBuffer.writeUInt16BE(0, 10);

    let offset = 12;
    for (const question of questions) {
        const labels = question.qname.split('.');
        for (const label of labels) {
            responseBuffer.writeUInt8(label.length, offset);
            offset += 1;
            responseBuffer.write(label, offset, 'utf8');
            offset += label.length;
        }
        responseBuffer.writeUInt8(0, offset);
        offset += 1;
        responseBuffer.writeUInt16BE(question.qtype, offset);
        offset += 2;
        responseBuffer.writeUInt16BE(question.qclass, offset);
        offset += 2;
    }

    for (const answer of answers) {
        const labels = answer.name.split('.');
        for (const label of labels) {
            responseBuffer.writeUInt8(label.length, offset);
            offset += 1;
            responseBuffer.write(label, offset, 'utf8');
            offset += label.length;
        }
        responseBuffer.writeUInt8(0, offset);
        offset += 1;
        responseBuffer.writeUInt16BE(answer.type, offset);
        offset += 2;
        responseBuffer.writeUInt16BE(answer.class, offset);
        offset += 2;
        responseBuffer.writeUInt32BE(answer.ttl, offset);
        offset += 4;
        responseBuffer.writeUInt16BE(answer.rdata.length, offset);
        offset += 2;
        answer.rdata.copy(responseBuffer, offset);
        offset += answer.rdata.length;
    }

    return responseBuffer.slice(0, offset);
};

export const onRequestGet = async ({ request }) => {
    const { method, headers, url } = request;
    const searchParams = new URL(url).searchParams;
    if (searchParams.has('dns')) {
        const dnsQuery = searchParams.get('dns');
        const parsedQuery = parseDnsQuery(dnsQuery);
        const { questions } = parsedQuery;
        const question = questions[0];
        const qname = question.qname;
        const qtype = question.qtype === 1 ? 'A' : question.qtype === 28 ? 'AAAA' : null;

        if (customRecords[qname] && customRecords[qname][qtype]) {
            const answers = customRecords[qname][qtype].map(ip => ({
                name: qname,
                type: qtype === 'A' ? 1 : 28,
                class: 1,
                ttl: 300,
                rdata: Buffer.from(ip.split('.').map(octet => parseInt(octet, 10)))
            }));
            const responseBuffer = buildDnsResponse(parsedQuery.transactionId, parsedQuery.flags, questions, answers);
            return new Response(responseBuffer, {
                status: 200,
                headers: {
                    'Content-Type': contype,
                }
            });
        } else {
            return await fetch(doh + '?dns=' + dnsQuery, {
                method: 'GET',
                headers: {
                    'Accept': contype,
                }
            });
        }
    } else if (method == 'GET' && headers.get('Accept') == jstontype) {
        const search = new URL(url).search;
        return await fetch(dohjson + search, {
            method: 'GET',
            headers: {
                'Accept': jstontype,
            }
        });
    } else {
        return new Response("", { status: 404 });
    }
};

export const onRequestPost = async ({ request }) => {
    const { headers } = request;
    if (headers.get('content-type') == contype) {
        const requestBody = await request.arrayBuffer();
        const parsedQuery = parseDnsQuery(Buffer.from(requestBody).toString('base64'));
        const { questions } = parsedQuery;
        const question = questions[0];
        const qname = question.qname;
        const qtype = question.qtype === 1 ? 'A' : question.qtype === 28 ? 'AAAA' : null;

        if (customRecords[qname] && customRecords[qname][qtype]) {
            const answers = customRecords[qname][qtype].map(ip => ({
                name: qname,
                type: qtype === 'A' ? 1 : 28,
                class: 1,
                ttl: 300,
                rdata: Buffer.from(ip.split('.').map(octet => parseInt(octet, 10)))
            }));
            const responseBuffer = buildDnsResponse(parsedQuery.transactionId, parsedQuery.flags, questions, answers);
            return new Response(responseBuffer, {
                status: 200,
                headers: {
                    'Content-Type': contype,
                }
            });
        } else {
            return fetch(doh, {
                method: 'POST',
                headers: {
                    'Accept': contype,
                    'Content-Type': contype,
                },
                body: request.body,
            });
        }
    } else {
        return new Response("", { status: 404 });
    }
};
