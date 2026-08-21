// internal/web/handlers/articles.go
package handlers

import (
	"html/template"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/jbrahy/AntiVirus/internal/web/config"
)

// Article is one editorial piece in the /articles section. Body is a slice
// of paragraphs rather than a single HTML blob so the template can render
// each one through html/template's normal auto-escaping — no paragraph
// needs to be marked safe, so none of this content can carry a script tag.
type Article struct {
	Slug    string
	Title   string
	Dek     string // one-sentence standfirst under the headline
	Date    string
	Section string
	Body    []string
}

var Articles = []Article{
	{
		Slug:    "a-brief-history-of-the-computer-virus",
		Title:   "A Brief History of the Computer Virus",
		Dek:     "Before ransomware and nation-state malware, there was a program that just wanted to say hello.",
		Date:    "July 18, 2026",
		Section: "History",
		Body: []string{
			"In 1986, two brothers running a computer shop in Lahore, Pakistan, wrote a program to stop customers from pirating their software. Basit and Amjad Farooq Alvi called it Brain, and it did something no one had really seen before: it copied itself, quietly, onto every floppy disk that touched an infected machine. It changed the disk's volume label, hid itself from casual inspection, and spread from computer to computer with no help from its authors. It is widely considered the first virus to infect IBM PC-compatible computers in the wild, and it worked exactly as designed for years after the Alvi brothers stopped caring about the software piracy that inspired it.",
			"The idea predates Brain by over a decade. In 1971, a researcher named Bob Thomas wrote an experimental program called Creeper that moved between computers on ARPANET, the Defense Department network that became the ancestor of the internet, printing the message \"I'm the creeper, catch me if you can.\" It did no damage. It was closer to a magic trick than a weapon: proof that a program could move itself between machines without being carried there by a person. A colleague, Ray Tomlinson, wrote a second program called Reaper whose only job was to hunt down and delete Creeper. It was, in effect, the first antivirus software, built before anyone had a reason to call it that.",
			"What changed the field from a curiosity into an industry was the Morris Worm, released in November 1988 by a Cornell graduate student named Robert Tappan Morris. Morris said later he intended it only to measure the size of the internet. A bug in its replication logic caused it to infect the same machines over and over, and it brought a meaningful fraction of the early internet, then a few tens of thousands of machines, to a crawl within hours. The Morris Worm led directly to the founding of the first Computer Emergency Response Team, at Carnegie Mellon, and to Morris becoming the first person convicted under the newly passed Computer Fraud and Abuse Act.",
			"Commercial antivirus software followed the threat, not the other way around. Companies that would become industry names, McAfee, Symantec, Sophos, all trace their antivirus products back to the late 1980s, built to catch a small and slow-growing number of known threats by checking files against a list. That approach, comparing a file against a catalog of things already known to be bad, is the same basic mechanism underneath every antivirus product sold today, NexGuard included. What has changed since 1986 is not the idea. It is the catalog's size, and the sophistication of what tries to avoid appearing in it.",
			"By the mid-1990s, the volume of new malware had outgrown what a human analyst could catalog by hand, and vendors began layering heuristics and behavioral analysis on top of signature matching, trying to catch what they had not yet seen. That tradeoff, between catching the known with near-perfect accuracy and guessing at the unknown with an acceptable error rate, is the central design tension of the entire field, and it has never fully resolved. It is also, four decades after two brothers in Lahore wanted to stop software piracy, still the first decision every antivirus company has to make.",
		},
	},
	{
		Slug:    "signatures-still-work",
		Title:   "Signatures Still Work: The Case for Exact Matching",
		Dek:     "Hash-based detection is treated as the industry's oldest, least glamorous tool. It is also its most reliable.",
		Date:    "July 22, 2026",
		Section: "Detection",
		Body: []string{
			"Ask a security researcher what signature-based detection cannot do, and the list comes quickly: it cannot catch malware it has never seen, it cannot catch a file that has been recompiled or even slightly altered, and it does nothing at all against an attacker who writes custom code for a single target. These are real limitations, and they are the reason signature matching has spent two decades being described in industry writing as legacy technology, a floor to build on rather than a solution in itself.",
			"What that framing tends to leave out is what signature matching actually buys, which is certainty. A cryptographic hash, most commonly SHA-256 in modern tools, reduces a file to a fixed-length fingerprint that changes completely if even a single bit of the file changes. When a scanner checks a file's hash against a list of hashes known to belong to malicious samples, a match is not a guess, a score, or a probability. It is confirmation that the file on the machine is byte-for-byte identical to a sample that was previously identified, analyzed, and cataloged as malicious. There is no false-positive rate to discuss, because there is no inference involved.",
			"That certainty has a cost, and the cost is coverage. A hash list only catches what has already been collected, analyzed, and added to it, and it catches nothing that has been modified since. Attackers know this, and automated tools that recompile or repack malware to produce a new hash for every deployment are common and cheap to run. This is the honest reason no serious vendor, including NexGuard, claims that hash matching alone is a complete antivirus strategy. It is a floor, not a ceiling.",
			"But a floor matters more than its critics usually credit. Large public malware-sharing efforts, the kind that feed threat-intelligence feeds used across the industry, catalog enormous numbers of confirmed-malicious samples precisely because so much real-world malware is reused, repackaged, and redeployed with only minor changes across many victims. A commodity infostealer sold on a criminal forum and installed on thousands of machines by dozens of unrelated buyers often does not change at all between installations. Hash matching catches that traffic with zero false positives and negligible computational cost, freeing more expensive and error-prone detection methods, heuristics, behavioral monitoring, machine-learning classifiers, to focus on what actually requires judgment.",
			"The industry's more sophisticated products layer these approaches rather than choosing between them, and that layering is the right architecture. But it is worth saying plainly, in an industry that markets almost exclusively on the sophistication of its newest detection method, that the oldest technique in the field still does the one thing none of the newer ones can promise: when it flags a file, it is not guessing.",
		},
	},
	{
		Slug:    "what-heuristics-actually-buy-you",
		Title:   "What Heuristics Actually Buy You, and What They Cost",
		Dek:     "Behavioral detection promises to catch the malware nobody has seen yet. It delivers that, and a second bill that rarely gets discussed.",
		Date:    "July 25, 2026",
		Section: "Detection",
		Body: []string{
			"Heuristic and behavioral detection exist to solve a problem signature matching cannot: catching malware on its first appearance, before anyone has analyzed a sample and added it to a list. Instead of asking whether a file matches something already known to be bad, a heuristic engine asks whether a file looks like it might be bad, based on patterns, and a behavioral engine watches what a running program actually does, flagging processes that encrypt large numbers of files quickly, inject code into other processes, or attempt to disable security tools, regardless of whether the executable itself has ever been seen before.",
			"This works, in the sense that it catches things signature matching structurally cannot. It is also the primary reason antivirus software has a reputation, well earned across decades, for slowing computers down and crying wolf. A heuristic engine is making a probabilistic judgment, and probabilistic judgments have error rates in both directions. A false negative lets real malware through. A false positive quarantines a legitimate program, and in security-conscious environments, particularly software development shops where compilers and build tools do genuinely unusual things to memory and the file system, false positives from behavioral engines are common enough to be a standing joke.",
			"The computational cost is real too. Watching every running process's behavior in real time, correlating actions across time and across processes, takes CPU cycles that signature matching, a single hash lookup, does not. This is the actual, unglamorous reason antivirus software earned its reputation for slowing machines down: not the scanning itself, but the always-on behavioral monitoring layered underneath it.",
			"None of this is an argument against heuristics. It is an argument for being honest about the tradeoff. A detection method that catches more unknowns necessarily makes more mistakes doing it, in both directions, and vendors that market behavioral detection as a strict improvement over signature matching, rather than a different tool with a different error profile, are eliding a real cost that shows up on their customers' machines as either a missed threat or an incorrectly quarantined file.",
			"The more defensible position, and the one the more careful security researchers have argued for years, is that these are complementary layers rather than competing generations of technology. Signatures handle the enormous volume of reused, commodity malware with zero ambiguity. Heuristics and behavioral analysis take the harder, genuinely uncertain cases that signatures cannot touch, and accept a worse error rate because the alternative, catching nothing new at all, is worse.",
		},
	},
	{
		Slug:    "inside-the-ransomware-economy",
		Title:   "Inside the Ransomware Economy",
		Dek:     "What began as a niche extortion tactic became a business model with suppliers, affiliates, and customer support.",
		Date:    "July 29, 2026",
		Section: "Threats",
		Body: []string{
			"On May 12, 2017, a piece of ransomware called WannaCry began spreading across the internet using a stolen and leaked National Security Agency exploit targeting a flaw in Microsoft Windows file-sharing. Within a day it had infected an estimated 200,000 computers across roughly 150 countries, disrupting Britain's National Health Service badly enough that some hospitals diverted ambulances and canceled surgeries. It was, at the time, one of the largest cyberattacks in history, and it demonstrated something the criminal underworld had suspected for years: encrypting a victim's files and demanding payment to unlock them scaled.",
			"Six weeks later, a second worm, NotPetya, spread through a compromised software update for a Ukrainian tax-accounting program and went on to cause an estimated ten billion dollars in damage worldwide, hitting the shipping giant Maersk, the pharmaceutical company Merck, and the delivery service FedEx's European subsidiary hard enough that some of them spent months on recovery. NotPetya is widely believed by Western governments to have been a Russian state operation disguised as ransomware, but the disguise itself was telling: by 2017, ransomware had become a convincing enough cover story that state actors used it.",
			"What followed was the professionalization of the crime. Ransomware-as-a-service platforms emerged, letting the people who write the encryption malware lease it to affiliates who handle the actual breach and deployment, splitting the ransom by an agreed percentage. Some groups run leak sites that publish stolen data from victims who refuse to pay, adding extortion on top of encryption. Others have published slickly written negotiation portals and, in more than one documented case, offered victims a discount for paying quickly, in language that reads uncomfortably close to a legitimate business's customer communications.",
			"The 2021 attack on Colonial Pipeline, which briefly shut down the largest fuel pipeline in the United States and led to gas shortages across the Southeast, was carried out by an affiliate using ransomware built by a group called DarkSide, and it illustrated how the affiliate model diffuses responsibility: DarkSide's operators publicly claimed they had not intended to cause the disruption their software caused, a claim that is easier to make when the software's author and its operator are two different people with two different incentives.",
			"None of this is solved by any single defensive tool, and no serious vendor should claim otherwise. But the ransomware economy's specific structure, small teams of developers, larger networks of affiliates, and widespread reuse of the same underlying encryption toolkits across many unrelated attacks, is exactly the pattern that makes maintained hash databases genuinely useful: the same ransomware binary, or a close variant of it, tends to show up again and again across victims who never had contact with each other, because the affiliate model runs on reuse.",
		},
	},
	{
		Slug:    "zero-days-and-the-market-nobody-talks-about",
		Title:   "Zero-Days and the Market Nobody Talks About",
		Dek:     "Software flaws nobody has patched yet are worth real money, and there is a functioning market to prove it.",
		Date:    "August 1, 2026",
		Section: "Industry",
		Body: []string{
			"A zero-day is a software vulnerability the vendor does not yet know about, named for the number of days the developer has had to fix it. Until it is discovered, reported, and patched, it works against every unpatched machine running the affected software, which makes it valuable in a very literal sense: there is a real, if largely unregulated, market that prices zero-day vulnerabilities based on the software they affect, the difficulty of exploiting them reliably, and how quietly they can be used before detection.",
			"Some of that market is entirely legitimate. Every major technology company runs a bug bounty program, paying independent researchers to find and report vulnerabilities before anyone else does, and specialized firms broker responsible disclosure between researchers and vendors as a business. These programs exist because the alternative, a researcher with no legal outlet for a serious finding, has historically pushed vulnerabilities toward buyers with fewer scruples about how they get used.",
			"The other side of that market is less publicly documented but not exactly hidden. Firms such as Zerodium have operated publicly for years, buying working exploits for major operating systems and applications and reselling access to them, by their own public statements, to government and law enforcement clients rather than publishing them or reporting them to the affected vendor. Published price lists for exploits affecting fully updated mobile operating systems have run into the millions of dollars, a figure that says more about the value of a working zero-day than any amount of industry commentary could.",
			"Governments are buyers in this market too, and not only as customers of commercial brokers. Intelligence and law enforcement agencies in multiple countries maintain their own vulnerability research capabilities, and the decision of whether to disclose a discovered flaw to the vendor, so it can be patched, or retain it for future use is a genuine and recurring policy debate, one the United States formalized through a process called the Vulnerabilities Equities Process. The tension is direct: every unpatched zero-day protects a capability and simultaneously endangers every other user of the affected software.",
			"For an ordinary user, none of this market activity is directly visible, and none of it is something an antivirus product can neutralize before the fact, by definition, a zero-day exploit has no existing signature and often no established behavioral pattern to flag. It is one honest limit of the entire industry, not a specific product's failure, and it is a large part of the reason security researchers consistently argue that patching promptly, not any single detection tool, remains the single highest-leverage defense most organizations have.",
		},
	},
	{
		Slug:    "when-the-update-is-the-attack",
		Title:   "When the Update Is the Attack: Supply Chain Compromise",
		Dek:     "The SolarWinds breach showed how attackers can skip the target and compromise the software everyone already trusts instead.",
		Date:    "August 5, 2026",
		Section: "Threats",
		Body: []string{
			"In December 2020, the security firm FireEye disclosed that it had been breached, and in the course of investigating its own compromise, discovered something far larger: attackers had inserted malicious code into a routine software update for Orion, a network-monitoring product made by a company called SolarWinds, used by tens of thousands of organizations including large parts of the United States federal government. Roughly 18,000 organizations downloaded the compromised update. A far smaller, more selectively targeted number were then actually exploited further by the attackers, who were widely attributed by U.S. officials to Russian intelligence.",
			"What made the SolarWinds breach different from a typical intrusion was where the attackers spent their effort. Rather than trying to break into thousands of individual targets one at a time, they compromised a single software vendor that thousands of targets already trusted enough to run its code with elevated system privileges and automatically install its updates. The update mechanism itself, the exact process organizations rely on to stay secure by staying current, was the delivery vehicle.",
			"This is what security researchers mean by a supply chain attack: compromising a trusted intermediary, a software vendor, a code library, a hardware component manufacturer, rather than the ultimate target directly. It is a harder attack to pull off, requiring access to a vendor's build systems or code repositories, but it pays off at a scale that direct intrusion rarely matches, and it exploits a form of trust that is difficult to remove from modern computing without also removing the convenience that makes automatic updates worth having in the first place.",
			"SolarWinds was not the first example and has not been the last. Attacks on open-source package repositories, where a widely used code library is compromised or a malicious package is published under a deceptively similar name to a popular one, have become common enough that major package managers now run automated scanning specifically looking for this pattern. The core vulnerability is structural, not specific to any one vendor: modern software is assembled from dozens or hundreds of dependencies that a development team did not write and, realistically, cannot fully audit.",
			"There is no clean technical fix for this, only mitigations: verifying cryptographic signatures on updates, minimizing the number of dependencies a system trusts, and treating a vendor's security practices as part of the actual attack surface rather than someone else's problem. It is also the strongest existing argument for open, auditable code as a category, not a specific software's marketing claim, since a supply chain compromise inserted into a project whose source is public and actively read by outsiders has a meaningfully shorter path to discovery than one inserted into a closed binary nobody outside the vendor can inspect.",
		},
	},
	{
		Slug:    "no-antivirus-catches-everything",
		Title:   "No Antivirus Catches Everything, and That's Worth Saying",
		Dek:     "The industry rarely advertises its own limits. It should, because understanding them is what makes the rest of a security strategy make sense.",
		Date:    "August 8, 2026",
		Section: "Industry",
		Body: []string{
			"Antivirus marketing has a genre convention, and the convention is the promise of completeness: total protection, all-in-one security, peace of mind. Independent testing labs that evaluate detection rates across large malware samples routinely publish numbers in the high nineties for major products, and those numbers are real, but they describe performance against samples the testing lab could collect, which by definition excludes malware novel enough that nobody has collected a sample of it yet.",
			"This is not a criticism of any specific product. It is a structural fact about the category. Detection, whichever method it uses, signature matching, heuristics, behavioral analysis, machine-learning classification, is fundamentally reactive to some degree: it depends on having encountered, or having built a model that generalizes from, something resembling the threat in front of it. A sufficiently novel, sufficiently targeted piece of malware, custom-built for one victim and never reused, is a genuinely hard problem for the entire industry, not a solved one that only weaker products fail at.",
			"Security researchers who study the field for a living talk about defense in depth for exactly this reason: no single control, including antivirus software, is expected to be sufficient on its own. Patching known vulnerabilities promptly, limiting what a compromised account or process can actually reach, backing up data in a way an attacker cannot also encrypt, and training people to recognize social engineering all sit alongside detection software as layers, each catching what the others miss, none of them claimed as complete.",
			"The honest version of an antivirus product's pitch is narrower than the marketing genre usually allows: it catches what it is built to catch, reliably and without pretending otherwise, and it says plainly what it does not do. A hash-based scanner that only claims to catch exact matches to known-malicious files is making a smaller promise than a product that claims to stop all threats, and it is, for exactly that reason, a promise it can actually keep.",
			"That smaller promise is not a weaker one in practice. Most real-world compromises, the ones that hit ordinary users and small organizations rather than nation-state targets, involve reused, commodity malware, not custom-built zero-days. A tool that is honest about only catching the known threats still catches the overwhelming majority of what people actually encounter. What it should not do, and what too much of the industry still does, is imply it catches the rest too.",
		},
	},
	{
		Slug:    "why-auditable-code-matters-more-than-marketing-claims",
		Title:   "Why Auditable Code Matters More Than Marketing Claims",
		Dek:     "Security software asks for more trust than almost any other category of program. Very little of it earns that trust the same way.",
		Date:    "August 12, 2026",
		Section: "Trust",
		Body: []string{
			"Antivirus software occupies an unusual position on a computer: it runs with elevated privileges, inspects files across the entire system, and, in many commercial products, phones home with telemetry about what it finds. Users are asked to trust that this access is used exactly as described, and for most of the industry's history, the only evidence offered for that trust has been a vendor's own privacy policy and reputation.",
			"Cryptography solved a version of this problem more than a century ago. In 1883, the Dutch cryptographer Auguste Kerckhoffs argued that a cipher should remain secure even if everything about its design is known to an adversary, except the key. The modern restatement, sometimes called Shannon's maxim, is blunter: assume the enemy knows the system. The principle reshaped cryptography because it forced designers to stop relying on secrecy of design as a security property, since secrecy of design cannot be verified by anyone outside the organization that holds it, and history is full of proprietary encryption schemes that turned out to be weak the moment someone outside the vendor finally examined them.",
			"Software security absorbed a version of the same lesson more slowly, through the open-source movement, and through what programmer Eric S. Raymond called Linus's Law in his essay on open development: given enough eyeballs, all bugs are shallow. The claim is not that open-source software is bug-free, it demonstrably is not, but that code visible to many independent readers has a shorter average path to having its flaws found than code only its own authors can see. ClamAV, an open-source antivirus engine first released in the late 1990s and still widely used, particularly on mail servers, is a direct, long-running example of the model applied to this specific category of software.",
			"Open source is not a synonym for secure, and code visibility alone does not guarantee anyone is actually reading it. But it does something closed source structurally cannot: it lets an independent party verify a specific, checkable claim, such as whether a program's only network activity is downloading a public hash list, rather than asking that claim to be taken on faith from the company that benefits from it being believed.",
			"For a category of software that asks for elevated system access and continuous trust, that difference is not a minor technical preference. It is close to the whole argument. A vendor that says its product does not upload user files or monitor behavior for any purpose beyond local detection is making a claim. A vendor whose source code is public, and whose claim can be checked against that code by anyone who chooses to look, is making a claim that can be tested rather than simply believed.",
		},
	},
	{
		Slug:    "mac-malware-grows-up",
		Title:   "Mac Malware Grows Up",
		Dek:     "\"Macs don't get viruses\" was never quite true. It has become far less true as Apple's install base grew.",
		Date:    "August 15, 2026",
		Section: "Threats",
		Body: []string{
			"For a long stretch of the 2000s and early 2010s, \"Macs don't get viruses\" was a genuinely defensible piece of folk wisdom, not because macOS was architecturally invulnerable, but because malware authors, like any economic actor, went where the volume was. Windows held the overwhelming majority of desktop market share, and building malware for a small, unusual minority platform was a poor use of criminal effort when the same effort aimed at Windows reached vastly more victims.",
			"That calculation has shifted as Apple's install base grew, and security researchers have tracked a steady rise in Mac-targeted malware over the years since, particularly adware and trojans distributed through fake software installers, cracked applications, and malicious browser extensions rather than the self-propagating worms that defined the Windows threat landscape of the 1990s and 2000s. The Mac threat model has always looked different from the Windows one, and it largely still does, but different is not the same as absent.",
			"One case that drew particular attention among researchers was Silver Sparrow, discovered in early 2021 shortly after Apple released its first Apple Silicon Macs. What made it notable was not primarily its payload, researchers who found it never observed it deliver a final malicious action, but the fact that it had already been compiled to run natively on Apple's brand-new M1 chip, showing that malware authors were tracking Apple's platform transitions closely enough to have working code ready near launch, not years behind it.",
			"macOS does carry real, built-in defenses that raise the cost of a successful attack: Gatekeeper checks that downloaded applications are signed by a known developer before allowing them to run without an explicit override, and XProtect, Apple's own built-in scanner, checks new files against a list of known-malicious signatures Apple maintains and updates. These are meaningfully useful and free, and they are also, structurally, the same kind of tool being discussed throughout this series: a maintained list of known threats, checked against what is actually on the machine.",
			"What built-in platform defenses do not cover is the wider ecosystem question of user choice: software installed outside the App Store, developer tools that need broader system access, and the ordinary human tendency to click through a security warning when a piece of software is wanted badly enough. Mac users who have spent a decade assuming the platform's reputation covers them are, on current evidence, assuming something that has become progressively less true, and a threat landscape that grows in proportion to a platform's popularity is not an exception to how malware economics work. It is the rule, arriving a little later than it did everywhere else.",
		},
	},
	{
		Slug:    "ai-in-malware-detection-promise-and-fine-print",
		Title:   "AI in Malware Detection: Promise, Hype, and the Fine Print",
		Dek:     "Machine learning genuinely changed parts of the detection landscape. It did not change all of the marketing claims made in its name.",
		Date:    "August 19, 2026",
		Section: "Industry",
		Body: []string{
			"Machine-learning classifiers earned their place in modern antivirus products by doing something genuinely useful: trained on large numbers of known-malicious and known-benign files, they can flag files that resemble malware structurally, in ways too subtle or too high-dimensional for a human analyst to encode as a simple rule, even when the specific file has never been seen before. This is a real capability, and major security vendors have used it in production for years to supplement, not replace, signature and heuristic detection.",
			"It is also a capability with well-documented failure modes that get less airtime in product marketing than the capability itself. Machine-learning classifiers are vulnerable to adversarial examples, inputs deliberately crafted to fool a specific model, and academic security researchers have published working demonstrations of malware modified in small, targeted ways specifically to slip past machine-learning-based detectors while keeping the same malicious functionality intact. A model trained on yesterday's malware family also does not automatically generalize to a genuinely novel one, and models need continuous retraining to stay current, which is itself an ongoing cost, not a one-time investment.",
			"There is a second, more mundane problem, which is that \"AI-powered\" became a marketing term roughly as fast as it became a real technique, and the two usages are not always easy to tell apart from a product page. Some products described as AI-driven are running meaningful trained models in production. Others are running the same heuristic rule sets the industry has used for two decades, relabeled for a stronger marketing story. Independent testing labs have periodically flagged this gap between claimed and actual methodology across the industry.",
			"None of this makes machine learning a bad tool. It makes it a tool with a real, checkable set of tradeoffs, the same way signature matching, heuristics, and behavioral analysis each have their own, and a security product's promotional copy is generally not the place those tradeoffs get disclosed. A model's false-positive rate on files unlike its training data, its vulnerability to adversarial crafting, and how recently it was last retrained are all, in principle, testable, verifiable facts about a specific product. In practice, they are rarely published alongside the marketing claim.",
			"The pattern here is consistent with the rest of the industry's history: a genuinely useful new technique arrives, gets deployed by serious vendors as one layer among several, and simultaneously gets absorbed into marketing language faster than most buyers can verify what is actually running underneath it. The technique is not the problem. The gap between the claim and what can be checked is the same gap that has shown up, in different forms, in every detection method this series has covered.",
		},
	},
}

// articlesIndexView and articleShowView carry the business identity the
// shared footer renders from, alongside the article data (see landingView
// in landing.go for the same pattern).
type articlesIndexView struct {
	Site     config.SiteInfo
	Articles []Article
}

type articleShowView struct {
	Site    config.SiteInfo
	Article Article
}

// ArticlesIndex renders the list of all articles, newest first (as they
// appear in the Articles slice).
func ArticlesIndex(tmpl *template.Template) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		view := articlesIndexView{Site: config.Site, Articles: Articles}
		if err := tmpl.ExecuteTemplate(w, "articles-index.html", view); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
		}
	}
}

// ArticleShow renders a single article by its slug, or 404s if the slug is
// not one of the known articles.
func ArticleShow(tmpl *template.Template) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		slug := chi.URLParam(r, "slug")
		for _, a := range Articles {
			if a.Slug == slug {
				view := articleShowView{Site: config.Site, Article: a}
				if err := tmpl.ExecuteTemplate(w, "articles-show.html", view); err != nil {
					http.Error(w, "internal error", http.StatusInternalServerError)
				}
				return
			}
		}
		http.NotFound(w, r)
	}
}
