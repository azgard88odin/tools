function Show-GitCheatSheet {
    $rocket = 0x1F680 | ConvertTo-Unicode
    $wrench = 0x1F6E0 | ConvertTo-Unicode
    $fileFolder = 0x1F4C1 | ConvertTo-Unicode
    $pageFacingUp = 0x1F4C4 | ConvertTo-Unicode
    $repeat = 0x1F501 | ConvertTo-Unicode
    $globe = 0x1F310 | ConvertTo-Unicode
    $crossMark = 0x274C | ConvertTo-Unicode
    $magnifyingGlass = 0x1F50D | ConvertTo-Unicode

    $cheatSheet = @"
Git Cheat Sheet
===============

$rocket  Common Startup Procedure
----------------------------
git init                                              # Initialize a new repo
git branch -m main                                    # Rename default branch to 'main'
git add .                                             # Add all files/directories in current directory
git remote add origin <url>                           # Add remote repository
git pull origin main --allow-unrelated-histories      # Pull remote main branch (if repo exists)
git push -u origin main                               # Push and set upstream
git push -u origin main --force                       # Push and set upstream, overwriting the online repo

$wrench  Config
---------
git config --global user.name "Your Name"             # Set global user name
git config --global user.email "you@example.com"      # Set global email
git config --list                                     # Show all config settings

$fileFolder  Repo Setup
------------
git clone <url>                                       # Clone remote repo
git init                                              # Initialize new local repo

$pageFacingUp  Staging & Committing
------------------------
git status                                            # Show working tree status
git add <file>                                        # Stage file(s)
git commit -m "message"                               # Commit changes
git log                                               # Show commit history

$repeat  Branching
------------
git branch                                            # List local branches
git checkout -b <branch>                              # Create and switch to new branch
git checkout <branch>                                 # Switch to existing branch
git merge <branch>                                    # Merge specified branch into current

$globe  Remote Repos
---------------
git remote -v                                         # Show remote URLs
git push                                              # Push changes to remote
git pull                                              # Pull latest from remote
git fetch                                             # Fetch updates from remote

$crossMark  Undo / Fix
-------------
git reset <file>                                      # Unstage file
git checkout -- <file>                                # Discard changes in file
git revert <commit>                                   # Create a new commit to undo one
git revert --hard HEAD                                # Return to last commited state

$magnifyingGlass  Extras
---------
git log                                               # Commit history
git diff                                              # Show unstaged changes
git stash                                             # Stash current changes
git stash pop                                         # Reapply stashed changes

"@

    Write-Host $cheatSheet -ForegroundColor Cyan
}

function Show-RegexCheatSheet {
    $anchor = 0x2693 | ConvertTo-Unicode
    $characterClass = 0x1F524 | ConvertTo-Unicode
    $specialChar = 0x1F4B2 | ConvertTo-Unicode
    $groupRange = 0x1F523 | ConvertTo-Unicode
    $quantifier = 0x2734,0xFE0F | ConvertTo-Unicode
    $assertion = 0x1F506 | ConvertTo-Unicode
    $stringReplacement = 0x267B,0xFE0F | ConvertTo-Unicode

    $cheatSheet = @"
Regex Cheat Sheet
=================

$anchor Anchors
------------------
^                                                   # Beginning of the line
$                                                   # End of string or end of line in multiline patterns
\A                                                  # Start of string
\Z                                                  # End of string
\b                                                  # Word boundry
\B                                                  # Not word boundry
\<                                                  # Start of word
\>                                                  # End of word

$characterClass Character Classes
------------------
\c                                                  # Control character
\s                                                  # White space
\S                                                  # Not white space
\d                                                  # Digit character
\D                                                  # Not digit character
\w                                                  # Word character
\W                                                  # Not word character
\x                                                  # Hexidecimal digit
\O                                                  # Octal digit

$specialChar Special Characters
------------------
\n                                                  # Newline character
\r                                                  # Carriage return
\t                                                  # Tab
\v                                                  # Vertical tab
\f                                                  # Form feed

$groupRange Groups and Ranges
------------------
.                                                   # Any character except newline
(a|b)                                               # a or b
(...)                                               # Group
(?:...)                                              # Passive non-capturing group
[abc]                                               # Range a or b or c
[^abc]                                              # Not a or b or c
[a-q]                                               # Lowercase letter from a to q
[A-Q]                                               # Uppercase letter from A to Q
[0-7]                                               # Digit from 0 to 7

$quantifier Quantifiers
------------------
*                                                   # 0 or more (non greedy)
+                                                   # 1 or more (greedy)
?                                                   # 0 or 1 (optional)
{3}                                                 # Exactly 3 times
{3,}                                                # 3 or more times
{3,5}                                               # 3 to 5 times

$assertion Assertions
------------------
?=                                                  # Positive Lookahead
?!                                                  # Negative Lookahead
?<=                                                 # Positive Lookbehind
?!=                                                 # Negative Lookbehind
?>                                                  # Once only
?()                                                 # Condition [if then]
?()|                                                # Condition [if then else]

$stringReplacement String replacement
------------------
# NOTE: some regex implementations use \ instead of $
`$n                                                 # nth non-passive group
`$2                                                 # 'xyz' in /^(abc(xyz))$/
`$1                                                 # 'xyz' in /^(?:abc)(xyz)$/
`$+                                                 # Last matched string
`$&                                                 # Entire matched string
"@
    Write-Host $cheatSheet -ForegroundColor Cyan
}

Export-ModuleMember -Function Show-GitCheatSheet, Show-RegexCheatSheet