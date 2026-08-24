# ELI5: secure-secrets-vault

*ELI5 = "Explain Like I'm 5" — a plain-language explanation with no jargon.
The technical version lives in [ARCHITECTURE.md](ARCHITECTURE.md).*

## What is this thing?

Imagine you have a **magic notebook** where you write all your passwords:
the one for your email, for games, for your favorite websites. But this
notebook has a superpower — everything written in it turns into
**unreadable scribbles** unless you say the magic words (your master
password).

This program is that notebook, but on your computer. It's one file where all
your secrets live, scrambled so nobody can read them without the magic words.

## Why not just write passwords in a regular file?

Because if someone steals your laptop (or you accidentally upload the file to
the internet), they could read everything. With our magic notebook, all they
get is gibberish. Even the most powerful computers would need millions of
years to unscramble it without the magic words.

## Why not use "password123" as the magic words?

Here's the sneaky part: bad guys don't sit at your computer guessing. They
have **robot armies** — programs that try millions of passwords per second.
"password123"? Tried in a microsecond.

So before we turn your secrets into scribbles, we deliberately make the
computer do **very slow, memory-hungry math** first. For you it's half a
second of waiting. For the robot army trying a billion wrong passwords,
it's... a billion times half a second. The math gets much harder.

That slow-math trick is called Argon2id, and yes, real cryptographers
designed it, not us. We just follow their recipe book.

## Why didn't you invent your own secret-scrambling math?

Great question! Imagine you're building a bridge. Would you invent your own
type of steel in your garage? Of course not — you'd use tested steel that
engineers have been perfecting for decades.

Secret-scrambling math is the same. There are recipes (like AES) that the
world's smartest people have been attacking for **decades**, trying to break
them — and failing. If I invented my own recipe, some tiny mistake would make
it look safe but be full of holes. And here's the scary part: **no test
would catch it**. Everything would work fine until a bad guy finds the hole.

So we use the battle-tested recipes from libraries that security experts
constantly check. What *we* built ourselves is everything around them — like
a builder who uses factory-made steel but designs the bridge himself.

## What happens when you save a password?

1. You type the magic words.
2. The computer does the slow math and gets a **key** — a number that exists
   only from your exact magic words + a pinch of random salt stored in the
   notebook.
3. Your new password gets scrambled using that key.
4. Before writing anything to disk, we check the result twice ("did I write
   everything correctly?" — this is called `fsync`), then swap the old file
   for the new one **in one instant move**. Why? So if the power goes out
   mid-save, you don't end up with a torn half-file.

## The line problem (or: why there's a bouncer)

Imagine two people try to write in the notebook at the exact same moment.
Without any coordination, the second writer overwrites the first — one
password just vanishes. Poof.

So the program makes everyone **wait in line**. Only one person writes at a
time; everyone else waits up to 10 seconds. If the line doesn't move (some
program froze holding the pen), you get a polite error instead of a lost
password.

## The time machine detector

Say something goes wrong and your notebook gets replaced by an older copy —
from yesterday, before you saved three new passwords. Everything looks fine!
But your new passwords are gone.

Our notebook has a defense: every save adds an invisible counter — 1, 2, 3...
On each open, the program checks: "is the number today bigger than the number
I remembered yesterday?" If it went backwards — alarm! "Someone rolled back
the notebook."

Honest disclaimer: this catches *accidents* (a sync program messing up, you
restoring an old backup). It won't stop a movie villain who rolls back
everything perfectly. But accidents are way more common than movie villains.

## The clipboard that cleans up after itself

When you copy a password to paste somewhere, real copies of your password
sit in the computer's clipboard. Forever. Until you copy something else. Any
program can peek at it.

So after copying, our program quietly starts a little helper in the
background. It waits ~20 seconds, peeks at the clipboard, and thinks: "is
this still exactly my password?" If yes — wipes it. If you already copied
something else — leaves it alone (it only cleans its own mess).

Fun detail: the helper doesn't carry the actual password to compare. It
carries a **fingerprint** of it. And even that fingerprint travels in a
temporary file that self-destructs right after use, not in plain sight where
any program could see it.

## What this does NOT protect from

Being honest matters more than looking cool:

- **If someone sees you type the master password** (camera over your shoulder,
  keylogger virus) — game over. No magic helps there.
- **While the vault is open**, a super-virus could grab the key from the
  computer's memory. That's a limitation of how all normal programs work.
- **If your master password is weak** ("password123") — the robot army wins.
  The program warns you about weak passwords, but can't stop you.
- **The program protects the notebook. It doesn't protect the room.** If a
  villain already controls your whole computer, no local program can help.

## TL;DR

- One encrypted file with all your secrets 🔒
- Opens only with your master password
- Uses world-tested encryption, not homemade stuff
- Safe against crashes, power cuts, and two programs fighting over one file
- Notices if someone swaps it for an older copy
- Honest about what it *can't* protect against

Want the grown-up version with all the details?
[ARCHITECTURE.md](ARCHITECTURE.md). На русском: [README_RU.md](README_RU.md).
