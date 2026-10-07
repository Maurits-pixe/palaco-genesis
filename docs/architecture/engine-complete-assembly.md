# ENGINE COMPLEET assembly

This document records the first repository assembly for ENGINE COMPLEET.

## Repository stance
- `/crates` remains the Rust constitutional and contract layer
- `/specs` holds canonical specifications
- `/engine` maps engine-domain ownership and sequencing
- `/services`, `/apps`, `/database`, and `/verification` define the next implementation surfaces

## Implementation boundary
The repository now distinguishes between:
- normative specifications in `/specs`
- executable Rust contracts in `/crates`
- future delivery surfaces in assembly directories

## Immediate implementation focus
1. constitutional core contracts
2. RIO core flow
3. engine and service assembly
4. later surface delivery
