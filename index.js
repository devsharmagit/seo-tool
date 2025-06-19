const axios = require('axios');
const cheerio = require('cheerio');

async function analyzeSEO(url) {
    try {
        // Fetch the page with Axios
        const { data: html } = await axios.get(url);
        const $ = cheerio.load(html);

        // Extract SEO data
        return {
            commonKeywords: getCommonKeywords($),
            metaDescription: getMetaDescription($),
            headings: {
                h1: getHeadings($, 'h1'),
                h2: getHeadings($, 'h2')
            },
            images: analyzeImages($),
            links: analyzeLinks($, url),
            title: getTitleData($),
            metaTags: {
                canonical: getCanonicalTag($),
                noindex: checkNoIndex($),
                openGraph: checkOpenGraph($)
            },
            technicalSEO: {
                wwwCanonicalization: checkWWWCanonicalization(url),
                robotsTxt: await checkRobotsTxt(url),
                schemaMarkup: checkSchema($)
            },
            searchPreview: generateSearchPreview($, url)
        };
        
    } catch (error) {
        console.error('SEO Analysis Error:', error.message);
        return { error: 'Failed to analyze the page' };
    }
}

// Helper functions
function getCommonKeywords($) {
    const text = $('body h1, body h2, body h3, body h4, body h5, body h6, body span, body p, body li').text().toLowerCase();
    const words = text.split(/\s+/).filter(word => word.length > 3);
    
    const wordCount = {};
    words.forEach(word => {
        word = word.replace(/[^a-z]/g, '');
        wordCount[word] = (wordCount[word] || 0) + 1;
    });

    const topKeywords = Object.entries(wordCount)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10)
        .map(([word]) => word)
        .join(' ');

    return {
        description: "Top 10 most frequent keywords found on the page",
        keywords: topKeywords || "No significant keywords found"
    };
}

function getMetaDescription($) {
    const description = $('meta[name="description"]').attr('content') || '';
    return {
        found: description.length > 0,
        length: description.length,
        content: description || 'No meta description found'
    };
}

function getHeadings($, tag) {
    const headings = $(tag).map((i, el) => $(el).text().trim()).get();
    return {
        count: headings.length,
        examples: headings.slice(0, 5) // Show first 5 as examples
    };
}

function analyzeImages($) {
    const images = $('img').map((i, el) => ({
        src: $(el).attr('src') || '',
        alt: $(el).attr('alt') || ''
    })).get();

    const missingAlt = images.filter(img => !img.alt).length;

    return {
        total: images.length,
        missingAlt,
        missingAltPercentage: Math.round((missingAlt / images.length) * 100) || 0,
        examples: images.filter(img => !img.alt).slice(0, 2)
    };
}

function analyzeLinks($, baseUrl) {
    const links = $('a').map((i, el) => $(el).attr('href')).get();
    const domain = new URL(baseUrl).hostname;

    const internal = links.filter(href => 
        href && (href.includes(domain) || href.startsWith('/') || href.startsWith('#'))
    ).length;

    return {
        total: links.length,
        internal,
        external: links.length - internal,
        ratio: (internal / links.length * 100).toFixed(1) + '% internal'
    };
}

function getTitleData($) {
    const title = $('title').text() || '';
    return {
        length: title.length,
        content: title || 'No title found'
    };
}

function getCanonicalTag($) {
    const canonical = $('link[rel="canonical"]').attr('href') || '';
    return {
        found: canonical.length > 0,
        url: canonical || 'No canonical tag found'
    };
}

function checkNoIndex($) {
    const robots = $('meta[name="robots"]').attr('content') || '';
    return {
        isNoIndex: robots.toLowerCase().includes('noindex')
    };
}

function checkOpenGraph($) {
    const ogTags = $('meta[property^="og:"]').length;
    return {
        found: ogTags > 0,
        count: ogTags
    };
}

function checkWWWCanonicalization(url) {
    return {
        hasWWW: url.includes('www.'),
        // In a real implementation, you'd check both versions
        recommendation: "Ensure either www or non-www version redirects to the preferred version"
    };
}

async function checkRobotsTxt(url) {
    try {
        const domain = new URL(url).origin;
        const { data } = await axios.get(`${domain}/robots.txt`);
        return {
            exists: true,
            disallowCount: (data.match(/Disallow:/g) || []).length
        };
    } catch {
        return {
            exists: false
        };
    }
}

function checkSchema($) {
    const schema = $('script[type="application/ld+json"]').length;
    return {
        found: schema > 0,
        count: schema
    };
}

function generateSearchPreview($, url) {
    const title = $('title').text() || 'No title';
    const description = $('meta[name="description"]').attr('content') || 'No description';
    
    return {
        title,
        url,
        description,
        previewText: `${title} - ${description.substring(0, 100)}...`
    };
}

// Example usage
analyzeSEO('https://www.24streetdentalphoenix.com')
    .then(results => console.log(results))
    .catch(console.error);