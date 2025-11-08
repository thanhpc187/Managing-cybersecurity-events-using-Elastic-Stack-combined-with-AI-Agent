# How to Verify Authorship

## Quick Check Methods

### 1. Check Git History

Verify original authorship using Git:
```bash
# View commit history
git log --all --format="%H %an %ae %ad %s" --date=short

# View file creation
git log --follow --format="%H %an %ae %ad" --date=short -- <file_path>

# View all contributors
git shortlog -sn
```

### 2. Search for Copyright Notices

Check for copyright notices in code:
```bash
# Search for copyright notices
grep -r "Copyright.*thanhpc187" . --include="*.py" --include="*.md"

# Search for repository URL
grep -r "github.com/thanhpc187" . --include="*.py" --include="*.md"
```

### 3. Check LICENSE File

Verify LICENSE file exists:
```bash
# Check if LICENSE exists
ls -la LICENSE

# View LICENSE content
cat LICENSE
```

## Original Author

**thanhpc187**
- GitHub: [@thanhpc187](https://github.com/thanhpc187)
- Repository: [Managing-cybersecurity-events-using-Elastic-Stack-combined-with-AI-Agent](https://github.com/thanhpc187/Managing-cybersecurity-events-using-Elastic-Stack-combined-with-AI-Agent)

## Attribution

If you use this code, please credit the original author (thanhpc187) and include a link to this repository.

## Contact

If you have questions about authorship or attribution, please open an issue on GitHub.

---

**Note**: This document is for informational purposes only.
