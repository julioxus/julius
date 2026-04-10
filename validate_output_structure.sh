#!/bin/bash
# Validate output directory structure according to OUTPUT_DIRECTORY_GUIDELINES.md

echo "🔍 VALIDATING OUTPUT DIRECTORY STRUCTURE"
echo "=========================================="

errors=0
warnings=0

# Check for forbidden directories
echo "Checking for forbidden directories..."
forbidden_dirs=("OUTPUT_DIR" "output" "tmp")

for dir in "${forbidden_dirs[@]}"; do
    if [ -d "$dir" ]; then
        echo "❌ ERROR: Forbidden directory found: $dir"
        echo "   → Should be: outputs/{engagement-name}/"
        ((errors++))
    fi
done

# Check for files in project root (excluding allowed files)
echo "Checking for temporary files in project root..."
allowed_files=(
    "README.md" "CLAUDE.md" "AGENTS.md" "CONTRIBUTING.md"
    "package.json" "package-lock.json" ".gitignore" ".env" ".mcp.json"
    "OUTPUT_DIRECTORY_GUIDELINES.md" "VALIDATION_CHECKLIST.md"
    "setup_engagement_structure.sh" "validate_output_structure.sh"
    "pyproject.toml"
)

for file in *.py *.md *.json *.txt *.html *.sh; do
    if [[ -f "$file" ]]; then
        allowed=false
        for allowed_file in "${allowed_files[@]}"; do
            if [[ "$file" == "$allowed_file" ]]; then
                allowed=true
                break
            fi
        done

        if [[ "$allowed" == false ]]; then
            echo "⚠️  WARNING: Temporary file in root: $file"
            echo "   → Should be in: outputs/{engagement}/ subdirectory"
            ((warnings++))
        fi
    fi
done

# Check outputs/ structure
if [ ! -d "outputs" ]; then
    echo "❌ ERROR: outputs/ directory missing"
    echo "   → Create with: mkdir outputs"
    ((errors++))
else
    echo "✅ outputs/ directory exists"

    # Check individual engagements
    for engagement_dir in outputs/*/; do
        if [ -d "$engagement_dir" ]; then
            engagement=$(basename "$engagement_dir")
            echo ""
            echo "📁 Validating: $engagement"

            # Check standard directories
            standard_dirs=("data" "reports" "logs" "processed")
            optional_dirs=("components")

            for dir in "${standard_dirs[@]}"; do
                if [ ! -d "$engagement_dir/$dir" ]; then
                    echo "   ⚠️  Missing standard directory: $engagement/$dir"
                    ((warnings++))
                fi
            done

            # Check data/ subdirectories
            if [ -d "$engagement_dir/data" ]; then
                for subdir in "reconnaissance" "findings"; do
                    if [ ! -d "$engagement_dir/data/$subdir" ]; then
                        echo "   ⚠️  Missing data subdirectory: $engagement/data/$subdir"
                        ((warnings++))
                    fi
                done
            fi

            # Check reports/ subdirectories
            if [ -d "$engagement_dir/reports" ]; then
                for subdir in "intermediate-reports" "appendix"; do
                    if [ ! -d "$engagement_dir/reports/$subdir" ]; then
                        echo "   ⚠️  Missing reports subdirectory: $engagement/reports/$subdir"
                        ((warnings++))
                    fi
                done
            fi

            # Check for proper naming convention
            if [[ ! "$engagement" =~ ^[a-z]+-[a-z0-9-]+$ ]]; then
                echo "   ⚠️  Non-standard naming: $engagement"
                echo "      → Should match: {platform}-{company} (e.g., hackerone-company)"
                ((warnings++))
            fi
        fi
    done
fi

echo ""
echo "=========================================="
echo "📊 VALIDATION SUMMARY"
echo "Errors: $errors"
echo "Warnings: $warnings"

if [ $errors -eq 0 ] && [ $warnings -eq 0 ]; then
    echo "✅ All checks passed! Structure is compliant."
    exit 0
elif [ $errors -eq 0 ]; then
    echo "⚠️  Structure is mostly compliant but has warnings."
    echo "💡 Run: ./setup_engagement_structure.sh {engagement-name} to fix missing directories"
    exit 1
else
    echo "❌ Structure has errors that must be fixed."
    echo "📖 See: OUTPUT_DIRECTORY_GUIDELINES.md"
    exit 2
fi