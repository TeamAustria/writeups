# The Otter Scrolls 

## Description
```
Behold the ancient Spellbook, a tome of arcane wisdom where spells cast by mystical Otters weave the threads of fate. Embark on this enchanted journey where the secrets of the blockchain will be revealed. Brave adventurers, your quest awaits; may your courage be as boundless as the magic that guides you.

- nc tos.nc.jctf.pro 31337
```

## Provided Files
```
- tos_docker.tar.gz
```

## Writeup

> [!NOTE]
> Writeup by [kdm](https://github.com/FRoith)
> Credit to [Philogic](https://github.com/PhilippSchweinzer) and [CallMeAlasca](https://github.com/CallMeAlasca) who worked with me on this challenge.

Inspecting the provided source files, it is clear that this is just a simple challenge that will get you familiar with the framework used for all the Blockchain challenges in this CTF. The dialect in use for coding the smart contracts is the "Move" smart contract language, which itself is based on Rust.

Ignoring the rest of the framework, that just makes the challenge work, here is the basic code of the Challenge:
```rust
module challenge::theotterscrolls {

    // ---------------------------------------------------
    // DEPENDENCIES
    // ---------------------------------------------------

    use sui::table::{Self, Table};
    use std::string::{Self, String};
    use std::debug;

    // ---------------------------------------------------
    // STRUCTS
    // ---------------------------------------------------

    public struct Spellbook has key {
        id: UID,
        casted: bool,
        spells: Table<u8, vector<String>>
    }

    // ---------------------------------------------------
    // FUNCTIONS
    // ---------------------------------------------------

    //The spell consists of five magic words, which have to be read in the correct order!

    fun init(ctx: &mut TxContext) {
        
        let mut all_words = table::new(ctx);

        let fire = vector[
            string::utf8(b"Blast"),
            string::utf8(b"Inferno"),
            string::utf8(b"Pyre"),
            string::utf8(b"Fenix"),
            string::utf8(b"Ember")
        ];

        let wind = vector[
            string::utf8(b"Zephyr"),
            string::utf8(b"Swirl"),
            string::utf8(b"Breeze"),
            string::utf8(b"Gust"),
            string::utf8(b"Sigil")
        ];

        let water = vector[
            string::utf8(b"Aquarius"),
            string::utf8(b"Mistwalker"),
            string::utf8(b"Waves"),
            string::utf8(b"Call"),
            string::utf8(b"Storm")
        ];

        let earth = vector[
            string::utf8(b"Tremor"),
            string::utf8(b"Stoneheart"),
            string::utf8(b"Grip"),
            string::utf8(b"Granite"),
            string::utf8(b"Mudslide")
        ];

        let power = vector[
            string::utf8(b"Alakazam"),
            string::utf8(b"Hocus"),
            string::utf8(b"Pocus"),
            string::utf8(b"Wazzup"),
            string::utf8(b"Wrath")
        ];

        table::add(&mut all_words, 0, fire); 
        table::add(&mut all_words, 1, wind); 
        table::add(&mut all_words, 2, water); 
        table::add(&mut all_words, 3, earth); 
        table::add(&mut all_words, 4, power); 

        let spellbook = Spellbook {
            id: object::new(ctx),
            casted: false,
            spells: all_words
        };

        transfer::share_object(spellbook);
    }

    public fun cast_spell(spell_sequence: vector<u64>, book: &mut Spellbook) {

        let fire = table::remove(&mut book.spells, 0);
        let wind = table::remove(&mut book.spells, 1);
        let water = table::remove(&mut book.spells, 2);
        let earth = table::remove(&mut book.spells, 3);
        let power = table::remove(&mut book.spells, 4);

        let fire_word_id = *vector::borrow(&spell_sequence, 0);
        let wind_word_id = *vector::borrow(&spell_sequence, 1);
        let water_word_id = *vector::borrow(&spell_sequence, 2);
        let earth_word_id = *vector::borrow(&spell_sequence, 3);
        let power_word_id = *vector::borrow(&spell_sequence, 4);

        let fire_word = vector::borrow(&fire, fire_word_id);
        let wind_word = vector::borrow(&wind, wind_word_id);
        let water_word = vector::borrow(&water, water_word_id);
        let earth_word = vector::borrow(&earth, earth_word_id);
        let power_word = vector::borrow(&power, power_word_id);

        if (fire_word == string::utf8(b"Inferno")) {
            if (wind_word == string::utf8(b"Zephyr")) {
                if (water_word == string::utf8(b"Call")) {
                    if (earth_word == string::utf8(b"Granite")) {
                        if (power_word == string::utf8(b"Wazzup")) {
                            book.casted = true;
                        }
                    }
                }
            }
        }
  
    }

    public fun check_if_spell_casted(book: &Spellbook): bool {
        let casted = book.casted;
        assert!(casted == true, 1337);
        casted
    }

}
```

The code of the smart contract is relatively simple, if a bit long:
When initialized, it creates five lists of five different spell words, which can then be invoked as part of the `cast_spell` function. This function very simply just checks if the vector of indices provided maps to the exact correct spell, and if that is the case, it sets the `casted` variable of the provided `spellbook` true.

The function `check_if_spell_casted` is the function the challenge uses to determine whether or not to give out the flag, which makes the solution already obvious. But the question is now, how can we use this framework correctly to send the compiled smart contract to the server, as it expects?

Well, again, the framework handles most of it for us already, and even provides a `solve.move` file, which defines the `solve` function with all the correct arguments the server will then attempt to call.
```rust
module solve::solve {

    // [*] Import dependencies
    use challenge::theotterscrolls;

    public fun solve(
        _spellbook: &mut theotterscrolls::Spellbook,
        _ctx: &mut TxContext
    ) {
        // Your code here...
    }

}
```

The solution that provides the flag then is just:
```rust
module solve::solve {

    // [*] Import dependencies
    use challenge::theotterscrolls;

    public fun solve(
        _spellbook: &mut theotterscrolls::Spellbook,
        _ctx: &mut TxContext
    ) {
        let spell: vector<u64> = vector[1,0,3,3,3];
        theotterscrolls::cast_spell(spell, _spellbook);
    }

}
```
But just before we can use this to procure the flag, we need to provide one more thing for it: The address of the challenge smart contract.

Luckily, if we just connect to the server with `nc` and send it whatever, it tells us the address it published to. And even better, this address never changes between runs, so we can just edit the `Move.toml` file and put in the address.
```toml
[package]
name = "challenge"
version = "0.0.1"
edition = "2024.beta"

[dependencies]
Sui = { git = "https://github.com/MystenLabs/sui.git", subdir = "crates/sui-framework/packages/sui-framework", rev = "devnet-v1.27.0" }

[addresses]
admin = "0xfccc9a421bbb13c1a66a1aa98f0ad75029ede94857779c6915b44f94068b921e"
challenge = "<ENTER ADDRESS OF THE PUBLISHED CHALLENGE MODULE HERE>"
```

After that, we just run the `run_client.sh` and we get the flag!
`justCTF{Th4t_sp3ll_looks_d4ngerous...keep_y0ur_distance}`
