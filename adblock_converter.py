import re
import os
import json
import time
import gzip
import shutil
import concurrent.futures
import multiprocessing
import requests
from functools import lru_cache
from tldextract import extract as tld_extract
from typing import List, Dict, Tuple, Optional
from pathlib import Path

# ======================== Configuration Handler ========================
class ConfigManager:
    _instance = None
    DEFAULT_CONFIG = {
        "sources": [
            "https://easylist.to/easylist/easylist.txt",
            "https://easylist.to/easylist/easyprivacy.txt"
        ],
        "cache_dir": "filter_cache",
        "output_dir": "optimized_lists",
        "max_age_hours": 24,
        "conversion": {
            "optimize_css": True,
            "remove_comments": False,
            "remove_duplicates": True
        },
        "parallel_processing": True,
        "max_download_workers": 8,
        "user_agent": "AdblockConverter/1.0"
    }

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.config = cls.DEFAULT_CONFIG.copy()
            cls._instance.config_file = "adblock_config.json"
            cls._instance.load_config()
        return cls._instance

    def load_config(self):
        try:
            if Path(self.config_file).exists():
                with open(self.config_file, 'r') as f:
                    self.config = {**self.DEFAULT_CONFIG, **json.load(f)}
        except Exception as e:
            print(f"⚠️ Config load error: {e}. Using defaults")

    def save_config(self):
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            print(f"⚠️ Config save error: {e}")

    def get(self, key: str, default=None):
        keys = key.split('.')
        val = self.config
        for k in keys:
            if isinstance(val, dict) and k in val:
                val = val[k]
            else:
                return default
        return val

    def update(self, updates: Dict):
        for key, value in updates.items():
            keys = key.split('.')
            d = self.config
            for k in keys[:-1]:
                d = d.setdefault(k, {})
            d[keys[-1]] = value
        self.save_config()

# ======================== Enhanced Source Manager ========================
class SourceManager:
    def __init__(self):
        self.config = ConfigManager()
        self.cache_dir = Path(self.config.get('cache_dir'))
        self.cache_dir.mkdir(exist_ok=True, parents=True)
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': self.config.get('user_agent')
        })

    def _cache_path(self, source: str) -> Path:
        filename = re.sub(r'[^\w\-_.]', '_', source)
        return self.cache_dir / f"{filename}.gz"

    def is_cached(self, source: str) -> bool:
        path = self._cache_path(source)
        if not path.exists():
            return False
            
        max_age = self.config.get('max_age_hours') * 3600
        return time.time() - path.stat().st_mtime <= max_age

    def fetch_source(self, source: str) -> str:
        cache_path = self._cache_path(source)
        if self.is_cached(source):
            with gzip.open(cache_path, 'rt', encoding='utf-8') as f:
                return f.read()
        
        if source.startswith('http'):
            print(f"🌐 Downloading {source}")
            try:
                response = self.session.get(source, timeout=15)
                response.raise_for_status()
                content = response.text
                
                with gzip.open(cache_path, 'wt', encoding='utf-8') as f:
                    f.write(content)
                return content
            except Exception as e:
                print(f"⚠️ Download error for {source}: {e}")
                if cache_path.exists():
                    print("↩️ Using stale cache")
                    with gzip.open(cache_path, 'rt', encoding='utf-8') as f:
                        return f.read()
                return ""
        elif Path(source).exists():
            with open(source, 'r', encoding='utf-8') as f:
                return f.read()
        return ""

    def fetch_sources_parallel(self, sources: List[str]) -> Dict[str, str]:
        """Parallel download for multiple sources"""
        max_workers = min(self.config.get('max_download_workers'), 8)
        results = {}
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_source = {executor.submit(self.fetch_source, src): src for src in sources}
            
            for future in concurrent.futures.as_completed(future_to_source):
                source = future_to_source[future]
                try:
                    results[source] = future.result()
                except Exception as e:
                    print(f"⚠️ Parallel download failed for {source}: {e}")
                    results[source] = ""
                    
        return results

    def get_sources(self) -> List[str]:
        return self.config.get('sources', [])

# ======================== Rule Converter ========================
class RuleConverter:
    NETWORK_MARKERS = ("||", "|", "/", "?", "*", "$")
    COSMETIC_MARKERS = ("##", "#@#")
    EXCEPTION_MARKERS = ("@@",)
    COMMENT_MARKER = "!"
    UBO_ALLOWED_OPTIONS = {
        'domain', 'third-party', 'script', 'image', 'stylesheet', 'object',
        'xmlhttprequest', 'media', 'subdocument', 'websocket', 'webrtc',
        'generichide', 'genericblock', 'popup', 'document', 'elemhide',
        'redirect', 'csp', 'header', 'removeparam', 'badfilter'
    }
    CSS_COMPLEX_PSEUDOS = {
        ":has-text", ":contains", ":matches-css", ":if", ":if-not", 
        ":xpath", ":nth-ancestor"
    }

    def __init__(self):
        self.config = ConfigManager()
        self.domain_pattern = re.compile(r'([a-z0-9.-]+\.[a-z]{2,})')
        self.options_pattern = re.compile(r'\$(?P<options>[^,\s]+)')
        self.css_splitter = re.compile(r'([#.\[])\s*')

    @lru_cache(maxsize=10000)
    def convert_rule(self, rule: str) -> str:
        stripped = rule.strip()
        if not stripped:
            return ""
        
        try:
            rule_type = self._classify_rule(stripped)
            
            if rule_type == "comment":
                return self._handle_comment(rule)
            if rule_type == "network":
                return self._optimize_network_rule(stripped)
            if rule_type == "cosmetic":
                return self._optimize_cosmetic_rule(stripped)
            if rule_type == "exception":
                return self._optimize_exception_rule(stripped)
            return self._handle_unknown_syntax(stripped)
        except Exception as e:
            return f"! Conversion error: {e} - Original: {rule}"

    def _classify_rule(self, rule: str) -> str:
        if rule.startswith(self.COMMENT_MARKER):
            return "comment"
        if rule.startswith(self.EXCEPTION_MARKERS):
            return "exception"
        if any(marker in rule for marker in self.COSMETIC_MARKERS):
            return "cosmetic"
        if any(rule.startswith(marker) or 
               any(marker in rule for marker in self.NETWORK_MARKERS)):
            return "network"
        return "other"

    def _optimize_network_rule(self, rule: str) -> str:
        if '$' not in rule:
            return self._tokenize_pattern(rule)
            
        pattern, options = rule.split('$', 1)
        pattern = pattern.rstrip()
        processed_pattern = self._tokenize_pattern(pattern)
        processed_options = self._process_options(options)
        
        if processed_options:
            return f"{processed_pattern}${processed_options}"
        return processed_pattern

    def _tokenize_pattern(self, pattern: str) -> str:
        if pattern.startswith("||"):
            domain = pattern[2:].split("/")[0]
            return f"||{domain}^" if '/' in pattern[2:] else pattern
        if pattern.startswith("|") and pattern.endswith("|"):
            return f"|{pattern[1:-1]}^"
        return pattern.replace("*", "^").replace("^http://", "http://")

    def _process_options(self, options: str) -> str:
        option_list = []
        seen = set()
        
        for opt in options.split(','):
            cleaned = self._clean_option(opt.strip())
            if cleaned and cleaned not in seen:
                option_list.append(cleaned)
                seen.add(cleaned)
                
        return ','.join(option_list)

    def _clean_option(self, option: str) -> str:
        if option == "elemhide" or option == "collapse":
            return ""
        if option == "object-subrequest":
            return "object"
        if '=' in option:
            key, value = option.split('=', 1)
            if key == "domain" or key == "denyallow":
                domains = {d.strip() for d in value.split('|') if d.strip()}
                optimized = self._optimize_domain_list(domains)
                return f"{key}={optimized}" if optimized else ""
            return option
        return option if option in self.UBO_ALLOWED_OPTIONS else ""

    def _optimize_cosmetic_rule(self, rule: str) -> str:
        if "#@#" in rule:
            return rule.replace("#@#", "#@#+js(abp")
            
        parts = rule.split("##", 1)
        domains = [d.strip() for d in parts[0].split(",") if d.strip()]
        selector = parts[1].strip()
        
        optimized_domains = self._optimize_domain_list(domains)
        optimized_selector = self._optimize_css(selector)
        
        if optimized_domains:
            return f"{optimized_domains}##{optimized_selector}"
        return f"##{optimized_selector}"

    def _optimize_css(self, selector: str) -> str:
        if any(pseudo in selector for pseudo in self.CSS_COMPLEX_PSEUDOS):
            return selector
        if not self.config.get('conversion.optimize_css'):
            return selector
            
        parts = self.css_splitter.split(selector)
        token_count = len(parts)
        if token_count <= 3:
            return selector
            
        optimized = []
        i = 0
        while i < token_count:
            token = parts[i]
            if token in (' ', '>', '+', '~'):
                optimized.append(token)
                i += 1
            elif i + 1 < token_count and parts[i+1] in ('[', '.', '#'):
                optimized.append(parts[i+1] + parts[i])
                i += 2
            else:
                optimized.append(token)
                i += 1
        
        return ''.join(reversed(optimized))

    def _optimize_exception_rule(self, rule: str) -> str:
        if '#@#' in rule:
            return rule.replace("#@#", "#@#+js(abp")
            
        parts = rule.split('$', 1)
        pattern = parts[0]
        options = parts[1] if len(parts) > 1 else ""
        processed = self._process_options(options)
        
        if processed:
            return f"{pattern}${processed}"
        return pattern

    def _optimize_domain_list(self, domains: List[str]) -> str:
        if not domains:
            return ""
            
        domain_map = {}
        for domain in domains:
            parsed = tld_extract(domain)
            root = f"{parsed.domain}.{parsed.suffix}"
            if root not in domain_map:
                domain_map[root] = set()
            if domain != root:
                domain_map[root].add(domain)
                
        result = []
        for root, subs in domain_map.items():
            if len(subs) > 3:
                result.extend(f"~{s}" for s in subs)
                result.append(root)
            else:
                result.append(root)
                result.extend(subs)
                
        return '|'.join(sorted(set(result), key=lambda d: d.strip('~')))

    def batch_convert(self, rules: List[str]) -> List[str]:
        if self.config.get('parallel_processing'):
            with multiprocessing.Pool() as pool:
                return pool.map(self.convert_rule, rules)
        return [self.convert_rule(rule) for rule in rules]

# ======================== Enhanced List Processor ========================
class ListProcessor:
    def __init__(self):
        self.config = ConfigManager()
        self.source_manager = SourceManager()
        self.converter = RuleConverter()
        self.output_dir = Path(self.config.get('output_dir'))
        self.output_dir.mkdir(exist_ok=True, parents=True)

    def _preprocess(self, content: str) -> List[str]:
        lines = content.splitlines()
        if self.config.get('conversion.remove_comments'):
            return [line for line in lines if not line.startswith('!')]
        return lines

    def _postprocess(self, rules: List[str]) -> List[str]:
        if self.config.get('conversion.remove_duplicates'):
            seen = set()
            unique = []
            for rule in rules:
                if rule and rule not in seen:
                    unique.append(rule)
                    seen.add(rule)
            return unique
        return rules

    def process_content(self, source: str, content: str) -> List[str]:
        print(f"🔧 Processing: {source}")
        if not content:
            print(f"❌ Empty content for: {source}")
            return []
            
        raw_rules = self._preprocess(content)
        converted = self.converter.batch_convert(raw_rules)
        return self._postprocess(converted)

    def process_source(self, source: str) -> List[str]:
        content = self.source_manager.fetch_source(source)
        return self.process_content(source, content)

    def process_all_sources(self) -> Dict[str, List[str]]:
        sources = self.source_manager.get_sources()
        contents = self.source_manager.fetch_sources_parallel(sources)
        
        results = {}
        for source, content in contents.items():
            results[source] = self.process_content(source, content)
            
        return results

    def generate_output(self, processed: Dict[str, List[str]]) -> Dict[str, Path]:
        outputs = {}
        for source, rules in processed.items():
            filename = Path(source).name.split('.')[0] + "_ublock.txt"
            output_path = self.output_dir / filename
            
            try:
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write("\n".join(rules))
                outputs[source] = output_path
                print(f"💾 Saved: {output_path}")
            except Exception as e:
                print(f"⚠️ Error saving {output_path}: {e}")
        return outputs

    def create_master_list(self, processed: Dict[str, List[str]]) -> Path:
        all_rules = []
        for rules in processed.values():
            all_rules.extend(rules)
            
        optimized = self._postprocess(all_rules)
        output_path = self.output_dir / "ublock_super.txt"
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                # Updated metadata
                f.write("! Title: uBlock Super\n")
                f.write("! Author: Murtaza Salih\n")
                f.write(f"! Version: {time.strftime('%Y.%m.%d')}\n")
                f.write(f"! Updated: {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())}\n")
                f.write(f"! Sources: {len(processed)}\n")
                f.write(f"! Total Rules: {len(optimized)}\n\n")
                f.write("\n".join(optimized))
            print(f"🏆 Master list created: {output_path}")
            return output_path
        except Exception as e:
            print(f"⚠️ Error creating master list: {e}")
            return None

# ======================== CLI & Main Control ========================
class AdblockConverterCLI:
    def __init__(self):
        self.config = ConfigManager()
        self.processor = ListProcessor()

    def run(self):
        print("\n" + "="*50)
        print("🚀 uBlock Super - Adblock List Optimizer")
        print("="*50)
        print("🧩 Sources:", len(self.config.get('sources')))
        print("⚙️ Parallel downloads:", self.config.get('max_download_workers'), "workers")
        print("⚡ Parallel processing:", "Enabled" if self.config.get('parallel_processing') else "Disabled")
        print("\nStarting processing...")
        
        start_time = time.time()
        
        try:
            processed = self.processor.process_all_sources()
            outputs = self.processor.generate_output(processed)
            master_path = self.processor.create_master_list(processed)
            
            elapsed = time.time() - start_time
            rules_count = sum(len(r) for r in processed.values())
            
            print("\n" + "="*50)
            print(f"✅ Processing complete in {elapsed:.2f} seconds")
            print(f"📜 Processed rules: {rules_count:,}")
            print(f"🔖 Master list: {master_path}")
            
            if outputs:
                print("\nIndividual lists:")
                for source, path in outputs.items():
                    print(f"  → {Path(source).name[:30]:<30} : {path}")
            print("="*50 + "\n")
            
        except Exception as e:
            print(f"\n🔥 Critical error: {e}")
            import traceback
            traceback.print_exc()

    def add_source(self, source: str):
        sources = self.config.get('sources')
        if source not in sources:
            sources.append(source)
            self.config.update({'sources': sources})
            print(f"✅ Added source: {source}")
        else:
            print(f"ℹ️ Source already exists: {source}")

    def remove_source(self, source: str):
        sources = self.config.get('sources')
        if source in sources:
            sources.remove(source)
            self.config.update({'sources': sources})
            print(f"🗑️ Removed source: {source}")
        else:
            print(f"ℹ️ Source not found: {source}")

    def clear_cache(self):
        cache_dir = Path(self.config.get('cache_dir'))
        if cache_dir.exists():
            shutil.rmtree(cache_dir)
            print("🧹 Cache cleared")
        else:
            print("ℹ️ Cache directory does not exist")

    def show_config(self):
        print("Current Configuration:")
        print(json.dumps(self.config.config, indent=2))

# ======================== Entry Point ========================
if __name__ == "__main__":
    cli = AdblockConverterCLI()
    cli.run()
