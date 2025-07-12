const axios = require('axios');
const cheerio = require('cheerio');
const { parse } = require('tldts');
const readline = require('readline');

async function analyzeHTML(url) {
    try {
        const { data: html } = await axios.get(url, {
            headers: { 'User-Agent': 'MySecurityScanner/1.0' }
        });
        const $ = cheerio.load(html);

        const result = {
            hasGetForm: false,
            externalScripts: [],
            usesEvalOrWrite: false,
            metaTags: [],
        };

        // 1. GET 메소드 사용 여부
        $('form').each((_, el) => {
            const method = $(el).attr('method');
            if (method && method.toLowerCase() === 'get') {
                result.hasGetForm = true;
            }
        });

        // 2. 외부 소스
        $('script[src]').each((_, el) => {
            const src = $(el).attr('src');
            const domain = parse(src).domain;
            if (domain && !url.includes(domain)) {
                result.externalScripts.push(src);
            }
        });

        // 3. 위험한 inline JS 함수 사용
        $('script').each((_, el) => {
            const code = $(el).html();
            if (code && /(eval|document\.write)/.test(code)) {
                result.usesEvalOrWrite = true;
            }
        });

        // 4. meta 보안 관련 태그
        $('meta').each((_, el) => {
            const name = $(el).attr('http-equiv') || $(el).attr('name');
            const content = $(el).attr('content');
            if (name && content) {
                result.metaTags.push({ name, content });
            }
        });
        return result;
    } catch (err) {
        return { error: `분석 중 오류 발생: ${err.message}`};
    }
}

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

rl.question('분석할 웹 사이트 주소(URL)을 입력하세요: ', async (input) => {
    const result = await analyzeHTML(input);

    console.log('\n----------분석 결과----------');
    if (result.error) {
        console.error(result.error);
    } else {
        console.log(`GET 메소드 사용 여부: ${result.hasGetForm}`);
        console.log(`외부 소스 사용 여부: ${result.externalScripts}`);
        console.log(`위험한 inline JS 사용 여부: ${result.usesEvalOrWrite}`);
        console.log(`메타 보안 정책 누락 여부: ${result.metaTags}`);
    }

    rl.close();
})