const whois = require('whois-json');
const dayjs = require('dayjs');
const readline = require('readline');
const { parse } = require('tldts');

function extractDomain(url) {
    const result = parse(url);
    return result.domain || null;
}

function validDate(info, candidates) {
    for (const key of candidates) {
        if (key in info) {
            const value = info[key];
            const parsed = dayjs(value);
            if (parsed.isValid()) {
                return parsed;
            }
        }
    }
    return null;
}


async function analyzeDomain(url) {
    try {
        const domain = extractDomain(url);
        if (!domain) return { error: '유효하지 않은 URL입니다.' };
        const info = await whois(domain);

        const creationDateKeys = ['createdDate', 'creationDate', 'registeredDate', 'Creation Date', 'Created On'];
        const expirationDateKeys = ['expiresDate', 'expirationDate', 'registryExpiryDate', 'registrarRegistrationExpirationDate', 'Registry Expiry Date', 'Registrar Registration Expiration Date'];

        const createdDate = validDate(info, creationDateKeys);
        const expiresDate = validDate(info, expirationDateKeys);

        let score = 0;
        const notes = [];

        // 1. 생성일
        if (createdDate && dayjs().diff(createdDate, 'year') < 1) {
            score += 30;
            notes.push('도메인이 1년 미만의 최근에 생성됨');
        } else if (!createdDate) {
            score += 10;
            notes.push('도메인 생성일을 확인할 수 없음');
        }

        // 2. 등록 기간
        if (expiresDate && expiresDate.diff(dayjs(), 'month') < 12) {
            score += 15;
            notes.push('도메인 등록 기간이 1년 이하');
        } else if (!expiresDate) {
            score += 10;
            notes.push('도메인 만료일을 확인할 수 없음');
        }

        // 3. 등록자 공개 여부
        const registrantFields = JSON.stringify(info).toLowerCase();
        if (registrantFields.includes('privacy') || registrantFields.includes('redacted')) {
            score += 20;
            notes.push('등록자 정보가 비공개 처리됨');
        }

        // 4. 위험 국가
        if (info.country && ['NG', 'RU', 'CN'].includes(info.country)) {
            score += 10;
            notes.push(`등록자 국가가 위험 국가(${info.country})로 분류됨`);
        }

        // WHOIS 원문 (디버깅용)
        console.log(info);

        return {
            domain,
            createdDate: createdDate? createdDate.format('YYYY-MM-DD') : '확인 불가',
            expiresDate: expiresDate? expiresDate.format('YYYY-MM-DD') : '확인 불가',
            score,
            notes,
        };
    } catch (error) {
        return {error: `분석 중 오류 발생: ${error.message}`};
    }
}

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

rl.question('분석할 웹 사이트 주소(URL)을 입력하세요: ', async (input) => {
    const result = await analyzeDomain(input);

    console.log('\n----------분석 결과----------');
    if (result.error) {
        console.error(result.error);
    } else {
        console.log(`도메인: ${result.domain}`);
        console.log(`생성일: ${result.createdDate}`);
        console.log(`만료일: ${result.expiresDate}`);
        console.log(`위험 점수: ${result.score}/100`);
        if (result.notes.length > 0) {
            console.log(`위험 요인: `);
            result.notes.forEach((note, i) => {
                console.log(` ${i + 1}. ${note}`);
            });
        } else {
            console.log("문제 없음");
        }
    }
    rl.close();
})