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

$magnifyingGlass  Extras
---------
git diff                                              # Show unstaged changes
git stash                                             # Stash current changes
git stash pop                                         # Reapply stashed changes

"@

    Write-Host $cheatSheet -ForegroundColor Cyan
}

Export-ModuleMember -Function Show-GitCheatSheet