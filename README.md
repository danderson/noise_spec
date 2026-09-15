
Noise
---------

PQNoise is a framework for crypto protocols based on post-quantum KEMs.

> [!CAUTION]
> This is a work in progress. Assume this specification is dangerously incorrect.
> If you found this because you're trying to implement PQNoise, refer instead to the
> [PQNoise paper][pqnoise] for the authoritative definition, and the
> [Noise Protocol Framework specification][noise] for the protocol machinery that the
> PQNoise paper references as a base.

This is my attempt to write an implementer-focused specification for [PQNoise][pqnoise],
in the same style as the excellent [Noise Protocol Framework specification][noise].

In their paper, the PQNoise authors rightly focus on justifying its modifications to
classical Noise, and on proving the properties of the new protocol they defined. This
makes it an excellent reference for cryptographers, but the information that programmers
need to implement PQNoise is diffused throughout as a result. The paper also assumes
that the reader already knows Noise in some detail, and presents PQNoise as a diff to apply.

I think the Noise specification is one of the nicest specs in cryptography, and I feel that
PQNoise deserves a similarly accessible specification for protocol implementers. Lamenting
the lack of such a spec, I decided to take a stab at doing it myself. After all, how hard
can it be?...

I was not involved in the design of Noise or PQNoise. I'm taking the Noise spec as a starting
point in terms of structure and presentation, and reworking it to describe PQNoise. My aim
is to faithfully transcribe the design from the [PQNoise paper][pqnoise], but with a focus on
the construction and implementation details. The spec states the security properties of various
PQNoise handshake patterns as fact, and defers to the PQNoise paper and expert cryptographers
for proofs and verification of those claims.

This is a work in progress. Feedback is welcome from people familiar with Noise and PQNoise,
but if you came here looking for something to help you implement PQNoise, you should _not_
use this spec as a reference. Refer instead to the [PQNoise paper][pqnoise] and the base
[Noise specification][noise].

[pqnoise]: https://eprint.iacr.org/2022/539
[noise]: https://noiseprotocol.org

Specification
---------------

The PQNoise specification is stored in [pqnoise.md](pqnoise.md) as Pandoc Markdown.
The [Makefile](Makefile) processes the source file to produce HTML and PDF.

Only a few Pandoc features are used:

 - Metadata at top of file.

 - Reference links use Pandoc's "implicit_header_references" (clicking on these
   links in the Github display doesn't do anything).

 - Zero-numbered lists (warning: the Github display of these numbered lists
   shows them starting at 1, instead of 0).

 - Table of contents and metadata headers added to output.

> [!NOTE]
> The PDF output is currently broken, due to a change in how Pandoc handles citations
> in its LaTeX output. Patches welcome to fix it, for now I'm just using the HTML output
> when I want to read the cooked spec instead of the markdown source.
>
> Also note that Github flavored markdown doesn't understand some of the Pandoc flavored
> markdown tables in pqnoise.md and renders them as line noise. The raw markdown is
> line-wrapped and quite readable, or you can grab the HTML and CSS files from the output
> directory and read those.