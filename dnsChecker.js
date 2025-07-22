import { promises as dns } from 'node:dns';
import readline from 'node:readline';

// 신뢰 점수 산정 기준
const SCORE_CRITERIA = {
  SPF: {
    exists: { score: 10, message: 'SPF 레코드가 존재합니다.' },
    not_exists: { score: -10, message: 'SPF 레코드가 존재하지 않습니다.' },
  },
  DMARC: {
    exists: { score: 10, message: 'DMARC 레코드가 존재합니다.' },
    not_exists: { score: -10, message: 'DMARC 레코드가 존재하지 않습니다.' },
  },
  NS: {
    reliable: { score: 10, message: '신뢰할 수 있는 네임서버를 사용합니다.' },
    unreliable: { score: -10, message: '무료 또는 신뢰도가 낮은 네임서버를 사용합니다.' },
  },
  CNAME: {
    normal: { score: 5, message: 'CNAME 레코드가 정상적으로 연결되어 있습니다.' },
    deprecated: { score: -15, message: 'CNAME 레코드가 폐기된 서비스에 연결된 것으로 보입니다.' },
  },
  A: {
    stable: { score: 5, message: '안정적인 IP 주소를 사용합니다 (클라우드 서비스).'},
    unstable: { score: -10, message: 'IP 주소가 불안정하거나 Fast Flux로 의심됩니다.'},
  },
  MX: {
    exists: { score: 5, message: 'MX 레코드가 존재합니다.' },
    not_exists: { score: -5, message: 'MX 레코드가 존재하지 않습니다.' },
  },
};

const RELIABLE_NS_PROVIDERS = ['cloudflare', 'aws', 'azure', 'google'];
const RELIABLE_IP_PROVIDERS = ['amazonaws', 'azure', 'google']; // A 레코드의 PTR 조회 결과로 판단

/**
 * 도메인 신뢰 점수를 계산하고 리포트를 생성합니다.
 * @param {string} domain - 분석할 도메인
 * @returns {Promise<void>}
 */
async function generateTrustReport(domain) {
  let totalScore = 0;
  const report = [];

  // 1. SPF 레코드 확인
  try {
    const spfRecords = await dns.resolveTxt(domain);
    const hasSpf = spfRecords.some(record => record.join('').startsWith('v=spf1'));
    if (hasSpf) {
      totalScore += SCORE_CRITERIA.SPF.exists.score;
      report.push(`✅ [+10] ${SCORE_CRITERIA.SPF.exists.message}`);
    } else {
      totalScore += SCORE_CRITERIA.SPF.not_exists.score;
      report.push(`❌ [-10] ${SCORE_CRITERIA.SPF.not_exists.message}`);
    }
  } catch (error) {
    if (error.code === 'ENODATA' || error.code === 'ENOTFOUND') {
        totalScore += SCORE_CRITERIA.SPF.not_exists.score;
        report.push(`❌ [-10] ${SCORE_CRITERIA.SPF.not_exists.message}`);
    } else {
        report.push(`⚠️ [0] SPF 레코드 확인 중 오류 발생: ${error.message}`);
    }
  }

  // 2. DMARC 레코드 확인
  try {
    const dmarcRecords = await dns.resolveTxt(`_dmarc.${domain}`);
    const hasDmarc = dmarcRecords.some(record => record.join('').startsWith('v=DMARC1'));
    if (hasDmarc) {
      totalScore += SCORE_CRITERIA.DMARC.exists.score;
      report.push(`✅ [+10] ${SCORE_CRITERIA.DMARC.exists.message}`);
    } else {
        totalScore += SCORE_CRITERIA.DMARC.not_exists.score;
        report.push(`❌ [-10] ${SCORE_CRITERIA.DMARC.not_exists.message}`);
    }
  } catch (error) {
    if (error.code === 'ENODATA' || error.code === 'ENOTFOUND') {
        totalScore += SCORE_CRITERIA.DMARC.not_exists.score;
        report.push(`❌ [-10] ${SCORE_CRITERIA.DMARC.not_exists.message}`);
    } else {
        report.push(`⚠️ [0] DMARC 레코드 확인 중 오류 발생: ${error.message}`);
    }
  }

  // 3. 네임서버(NS) 신뢰성 확인
  try {
    const nsRecords = await dns.resolveNs(domain);
    const isReliable = nsRecords.some(ns => RELIABLE_NS_PROVIDERS.some(provider => ns.toLowerCase().includes(provider)));
    if (isReliable) {
      totalScore += SCORE_CRITERIA.NS.reliable.score;
      report.push(`✅ [+10] ${SCORE_CRITERIA.NS.reliable.message} (${nsRecords.join(', ')})`);
    } else {
      totalScore += SCORE_CRITERIA.NS.unreliable.score;
      report.push(`❌ [-10] ${SCORE_CRITERIA.NS.unreliable.message} (${nsRecords.join(', ')})`);
    }
  } catch (error) {
    report.push(`⚠️ [0] NS 레코드 확인 중 오류 발생: ${error.message}`);
  }

  // 4. CNAME 외부 연결 상태 확인 (www 서브도메인 기준)
  try {
    await dns.resolveCname(`www.${domain}`);
    // CNAME이 존재하고 에러 없이 확인되면 정상으로 간주
    totalScore += SCORE_CRITERIA.CNAME.normal.score;
    report.push(`✅ [+5] ${SCORE_CRITERIA.CNAME.normal.message}`);
  } catch (error) {
    if (error.code === 'ENODATA') {
        // CNAME이 없는 경우, A 레코드를 직접 사용하는 경우이므로 점수 변동 없음
        report.push(`ℹ️ [0] www 서브도메인에 CNAME 레코드가 없습니다. (A 레코드 직접 사용)`);
    } else if (error.code === 'ENOTFOUND') {
        // 폐기된 서비스로 연결될 경우 ENOTFOUND 에러가 발생할 수 있음
        totalScore += SCORE_CRITERIA.CNAME.deprecated.score;
        report.push(`❌ [-15] ${SCORE_CRITERIA.CNAME.deprecated.message}`);
    } else {
        report.push(`⚠️ [0] CNAME 레코드 확인 중 오류 발생: ${error.message}`);
    }
  }


  // 5. A 레코드 IP 안정성 확인
  try {
    const aRecords = await dns.resolve4(domain);
    if (aRecords && aRecords.length > 0) {
        // 여러 IP를 사용하는 경우 Fast Flux 가능성 (여기서는 간단하게 5개 이상일 경우로 가정)
        if (aRecords.length >= 5) {
            totalScore += SCORE_CRITERIA.A.unstable.score;
            report.push(`❌ [-10] ${SCORE_CRITERIA.A.unstable.message} (발견된 IP: ${aRecords.length}개)`);
        } else {
            // IP의 PTR 레코드를 조회하여 신뢰성 확인
            const reverseLookups = await Promise.all(aRecords.map(ip => dns.reverse(ip).catch(() => '')));
            const isStableIp = reverseLookups.some(ptr => RELIABLE_IP_PROVIDERS.some(provider => ptr[0] && ptr[0].toLowerCase().includes(provider)));

            if(isStableIp) {
                totalScore += SCORE_CRITERIA.A.stable.score;
                report.push(`✅ [+5] ${SCORE_CRITERIA.A.stable.message} (PTR: ${reverseLookups.flat().join(', ')})`);
            } else {
                // 특정 클라우드 제공업체가 아닌 경우 점수 변동 없음
                 report.push(`ℹ️ [0] A 레코드가 클라우드 제공업체 IP가 아닐 수 있습니다. (PTR: ${reverseLookups.flat().join(', ') || 'N/A'})`);
            }
        }
    } else {
        report.push(`⚠️ [0] A 레코드를 찾을 수 없습니다.`);
    }
  } catch (error) {
     if (error.code !== 'ENODATA' && error.code !== 'ENOTFOUND') {
        report.push(`⚠️ [0] A 레코드 확인 중 오류 발생: ${error.message}`);
     }
  }

  // 6. MX 레코드 확인
  try {
    const mxRecords = await dns.resolveMx(domain);
    if (mxRecords && mxRecords.length > 0) {
      totalScore += SCORE_CRITERIA.MX.exists.score;
      report.push(`✅ [+5] ${SCORE_CRITERIA.MX.exists.message}`);
    } else {
      totalScore += SCORE_CRITERIA.MX.not_exists.score;
      report.push(`❌ [-5] ${SCORE_CRITERIA.MX.not_exists.message}`);
    }
  } catch (error) {
     if (error.code === 'ENODATA' || error.code === 'ENOTFOUND') {
        totalScore += SCORE_CRITERIA.MX.not_exists.score;
        report.push(`❌ [-5] ${SCORE_CRITERIA.MX.not_exists.message}`);
    } else {
        report.push(`⚠️ [0] MX 레코드 확인 중 오류 발생: ${error.message}`);
    }
  }


  // 최종 리포트 출력
  console.log('---');
  console.log(`🔎 도메인 신뢰도 분석 리포트: ${domain}`);
  console.log('---');
  report.forEach(line => console.log(line));
  console.log('---');
  console.log(`💯 총 점수: ${totalScore}`);
  console.log('---');
}


// --- 실행 ---
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

function startAnalyzer() {
  rl.question('🔎 분석할 도메인이나 URL을 입력하세요 (종료하려면 exit 입력): ', async (input) => {
    const trimmedInput = input.trim();

    if (trimmedInput.toLowerCase() === 'exit') {
      rl.close();
      return;
    }

    if (!trimmedInput) {
      console.log('⚠️ 아무것도 입력되지 않았습니다. 다시 입력해주세요.');
      startAnalyzer();
      return;
    }

    let domainToAnalyze = trimmedInput;

    // URL을 입력했는지 확인하고, 맞다면 도메인만 추출
    try {
      // URL 생성자에 http:// 프로토콜이 없으면 에러가 나므로, 없는 경우 붙여줌
      const potentialUrl = !trimmedInput.startsWith('http') ? `http://${trimmedInput}` : trimmedInput;
      const urlObject = new URL(potentialUrl);
      
      // urlObject.hostname이 실제 도메인과 다를 때만 메시지 표시 (예: path가 있는 경우)
      if (urlObject.hostname !== trimmedInput.split('/')[0]) {
        domainToAnalyze = urlObject.hostname;
        console.log(`\nℹ️ 입력하신 주소에서 도메인 '${domainToAnalyze}'을(를) 추출하여 분석합니다.`);
      }
    } catch (e) {
      // URL 형식이 아니면 입력값 그대로를 도메인으로 사용
    }

    await generateTrustReport(domainToAnalyze);
    startAnalyzer(); // 다음 분석을 위해 다시 호출
  });
}

console.log("🚀 도메인 신뢰도 분석기를 시작합니다.");
startAnalyzer();