use base_hooks_bindings::{
    hooks_perpetual_auction::HooksPerpetualAuction,
    uniswap_v2_arb_hook::UniswapV2ArbHook,
};
use alloy_sol_types::{SolCall};

use alloy_primitives::{Address, B256, U256, TxKind, Bytes};
use std::str::FromStr;
use alloy_consensus::TxEip1559;
use op_alloy_consensus::OpTypedTransaction;
use reth_primitives::Recovered;
use reth_optimism_primitives::OpTransactionSigned;
use reth_evm::Evm;
use reth_provider::ProviderError;
use revm::Database;
use crate::tx_signer::Signer;

pub struct HooksPerpetualAuctionHelper;

impl HooksPerpetualAuctionHelper {
    pub fn get_hook(
        evm: &mut impl Evm,
        auction_contract: Address,
        contract_addr: Address,
        topic0: B256,
    ) -> Result<HooksPerpetualAuction::Hook, Box<dyn std::error::Error>> {
        let call = HooksPerpetualAuction::getHookCall {
            contractAddr: contract_addr,
            topic0,
        };

        let call_data = call.abi_encode();
        let result = evm.transact_system_call(Address::ZERO, auction_contract, call_data.into()).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

        let hook_data = HooksPerpetualAuction::getHookCall::abi_decode_returns(result.result.output().unwrap()).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        Ok(hook_data)
    }

    pub fn get_hooks_tuple(
        evm: &mut impl Evm,
        auction_contract: Address,
        contract_addr: Address,
        topic0: B256,
    ) -> Result<(Address, Address, U256, U256, U256), Box<dyn std::error::Error>> {
        let call = HooksPerpetualAuction::hooksCall {
            _0: contract_addr,
            _1: topic0,
        };

        let call_data = call.abi_encode();
        let result = evm.transact_system_call(Address::ZERO, auction_contract, call_data.into()).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

        let hook_data = HooksPerpetualAuction::hooksCall::abi_decode_returns(result.result.output().unwrap()).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        Ok((hook_data.owner, hook_data.entrypoint, hook_data.feePerCall, hook_data.deposit, hook_data.callsRemaining))
    }

    pub fn get_max_originator_share(
        evm: &mut impl Evm,
        auction_contract: Address,
    ) -> Result<U256, Box<dyn std::error::Error>> {
        let call = HooksPerpetualAuction::MAX_ORIGINATOR_SHARECall {};
        let call_data = call.abi_encode();
        let result = evm.transact_system_call(Address::ZERO, auction_contract, call_data.into()).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

        let share = HooksPerpetualAuction::MAX_ORIGINATOR_SHARECall::abi_decode_returns(result.result.output().unwrap()).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        Ok(share)
    }

    pub fn get_min_calls_deposit(
        evm: &mut impl Evm,
        auction_contract: Address,
    ) -> Result<U256, Box<dyn std::error::Error>> {
        let call = HooksPerpetualAuction::MIN_CALLS_DEPOSITCall {};
        let call_data = call.abi_encode();
        let result = evm.transact_system_call(Address::ZERO, auction_contract, call_data.into()).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

        let deposit = HooksPerpetualAuction::MIN_CALLS_DEPOSITCall::abi_decode_returns(result.result.output().unwrap()).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        Ok(deposit)
    }

    pub fn get_excess_eth(
        evm: &mut impl Evm,
        auction_contract: Address,
    ) -> Result<U256, Box<dyn std::error::Error>> {
        let call = HooksPerpetualAuction::getExcessETHCall {};
        let call_data = call.abi_encode();
        let result = evm.transact_system_call(Address::ZERO, auction_contract, call_data.into()).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

        let excess = HooksPerpetualAuction::getExcessETHCall::abi_decode_returns(result.result.output().unwrap()).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        Ok(excess)
    }

    pub fn get_hook_gas_stipend(
        evm: &mut impl Evm,
        auction_contract: Address,
    ) -> Result<U256, Box<dyn std::error::Error>> {
        let call = HooksPerpetualAuction::hookGasStipendCall {};
        let call_data = call.abi_encode();
        let result = evm.transact_system_call(Address::ZERO, auction_contract, call_data.into()).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

        let stipend = HooksPerpetualAuction::hookGasStipendCall::abi_decode_returns(result.result.output().unwrap()).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        Ok(stipend)
    }

    pub fn get_originator_share_bps(
        evm: &mut impl Evm,
        auction_contract: Address,
    ) -> Result<U256, Box<dyn std::error::Error>> {
        let call = HooksPerpetualAuction::originatorShareBpsCall {};
        let call_data = call.abi_encode();
        let result = evm.transact_system_call(Address::ZERO, auction_contract, call_data.into()).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

        let share_bps = HooksPerpetualAuction::originatorShareBpsCall::abi_decode_returns(result.result.output().unwrap()).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        Ok(share_bps)
    }

    pub fn get_owner(
        evm: &mut impl Evm,
        auction_contract: Address,
    ) -> Result<Address, Box<dyn std::error::Error>> {
        let call = HooksPerpetualAuction::ownerCall {};
        let call_data = call.abi_encode();
        let result = evm.transact_system_call(Address::ZERO, auction_contract, call_data.into()).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

        let owner = HooksPerpetualAuction::ownerCall::abi_decode_returns(result.result.output().unwrap()).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        Ok(owner)
    }

    pub fn get_total_reserved_eth(
        evm: &mut impl Evm,
        auction_contract: Address,
    ) -> Result<U256, Box<dyn std::error::Error>> {
        let call = HooksPerpetualAuction::totalReservedETHCall {};
        let call_data = call.abi_encode();
        let result = evm.transact_system_call(Address::ZERO, auction_contract, call_data.into()).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

        let reserved = HooksPerpetualAuction::totalReservedETHCall::abi_decode_returns(result.result.output().unwrap()).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        Ok(reserved)
    }

    pub fn execute_hook<E>(
        evm: &mut E,
        auction_contract: Address,
        contract_addr: Address,
        topic0: B256,
        topic1: B256,
        topic2: B256,
        topic3: B256,
        event_data: Vec<u8>,
        originator: Address,
    ) -> Result<Recovered<OpTransactionSigned>, Box<dyn std::error::Error>>
    where
        E: Evm,
        E::DB: Database<Error = ProviderError>,
    {
        // Step 1: Create signer and address from private key
        let private_key_hex = "0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6";
        let private_key_b256 = B256::from_str(private_key_hex)
            .map_err(|e| format!("Failed to parse private key: {:?}", e))?;
        let signer = Signer::try_from_secret(private_key_b256)
            .map_err(|e| format!("Failed to create signer: {:?}", e))?;

        let nonce = match evm.db_mut().basic(signer.address)? {
            Some(acc) => {
                acc.nonce
            },
            None => {
                return Err(format!("Account not found: {:?}", signer.address).into());
            }
        };


        // Encode the function call
        let call = HooksPerpetualAuction::executeHookCall {
            contractAddr: contract_addr,
            topic0,
            topic1,
            topic2,
            topic3,
            eventData: event_data.into(),
            originator,
        };
        let call_data = call.abi_encode();

        // Step 2: Create EIP-1559 transaction (using base_fee passed as parameter)
        let tx = OpTypedTransaction::Eip1559(TxEip1559 {
            chain_id: evm.chain_id(),
            nonce,
            gas_limit: 300_000_000,
            max_fee_per_gas: 300_000_000,
            max_priority_fee_per_gas: 1_000,
            to: TxKind::Call(auction_contract),
            value: U256::ZERO,
            input: Bytes::from(call_data),
            access_list: Default::default(),
        });

        // Step 3: Sign the transaction using the Signer
        let signed_tx = signer.sign_tx(tx)
            .map_err(|e| format!("Failed to sign transaction: {:?}", e))?;

        Ok(signed_tx)
    }
}

pub struct UniswapV2ArbHookHelper;

impl UniswapV2ArbHookHelper {
    pub fn get_supported_dex_count(
        evm: &mut impl Evm,
        contract_addr: Address,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        let call = UniswapV2ArbHook::getSupportedDEXCountCall {}.abi_encode();
        let result = evm.transact_system_call(Address::ZERO, contract_addr, call.into()).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

        let count: alloy_primitives::Uint<256, 4> = UniswapV2ArbHook::getSupportedDEXCountCall::abi_decode_returns(result.result.output().unwrap()).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        Ok(count.to())
    }

    pub fn get_supported_dex(
        evm: &mut impl Evm,
        contract_addr: Address,
        index: U256,
    ) -> Result<Address, Box<dyn std::error::Error>> {
        let call = UniswapV2ArbHook::supportedDEXesCall(index);
        let call_data = call.abi_encode();
        let result = evm.transact_system_call(Address::ZERO, contract_addr, call_data.into()).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

        let dex_address = UniswapV2ArbHook::supportedDEXesCall::abi_decode_returns(result.result.output().unwrap()).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        Ok(dex_address)
    }

    pub fn get_dex_info(
        evm: &mut impl Evm,
        contract_addr: Address,
        router: Address,
    ) -> Result<UniswapV2ArbHook::DEXConfig, Box<dyn std::error::Error>> {
        let call = UniswapV2ArbHook::getDEXInfoCall { router };
        let call_data = call.abi_encode();
        let result = evm.transact_system_call(Address::ZERO, contract_addr, call_data.into()).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

        let dex_config = UniswapV2ArbHook::getDEXInfoCall::abi_decode_returns(result.result.output().unwrap()).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        Ok(dex_config)
    }

    pub fn get_dex_configs(
        evm: &mut impl Evm,
        contract_addr: Address,
        router: Address,
    ) -> Result<(Address, String, bool), Box<dyn std::error::Error>> {
        let call = UniswapV2ArbHook::dexConfigsCall(router);
        let call_data = call.abi_encode();
        let result = evm.transact_system_call(Address::ZERO, contract_addr, call_data.into()).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

        let config = UniswapV2ArbHook::dexConfigsCall::abi_decode_returns(result.result.output().unwrap()).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        Ok((config.router, config.name, config.enabled))
    }

    pub fn is_authorized_token(
        evm: &mut impl Evm,
        contract_addr: Address,
        token: Address,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let call = UniswapV2ArbHook::authorizedTokensCall(token);
        let call_data = call.abi_encode();
        let result = evm.transact_system_call(Address::ZERO, contract_addr, call_data.into()).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

        let authorized = UniswapV2ArbHook::authorizedTokensCall::abi_decode_returns(result.result.output().unwrap()).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        Ok(authorized)
    }

    pub fn get_gas_cost_buffer(
        evm: &mut impl Evm,
        contract_addr: Address,
    ) -> Result<U256, Box<dyn std::error::Error>> {
        let call = UniswapV2ArbHook::gasCostBufferCall {};
        let call_data = call.abi_encode();
        let result = evm.transact_system_call(Address::ZERO, contract_addr, call_data.into()).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

        let buffer = UniswapV2ArbHook::gasCostBufferCall::abi_decode_returns(result.result.output().unwrap()).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        Ok(buffer)
    }

    pub fn get_max_trade_size(
        evm: &mut impl Evm,
        contract_addr: Address,
    ) -> Result<U256, Box<dyn std::error::Error>> {
        let call = UniswapV2ArbHook::maxTradeSizeCall {};
        let call_data = call.abi_encode();
        let result = evm.transact_system_call(Address::ZERO, contract_addr, call_data.into()).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

        let max_size = UniswapV2ArbHook::maxTradeSizeCall::abi_decode_returns(result.result.output().unwrap()).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        Ok(max_size)
    }

    pub fn get_min_profit_threshold(
        evm: &mut impl Evm,
        contract_addr: Address,
    ) -> Result<U256, Box<dyn std::error::Error>> {
        let call = UniswapV2ArbHook::minProfitThresholdCall {};
        let call_data = call.abi_encode();
        let result = evm.transact_system_call(Address::ZERO, contract_addr, call_data.into()).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

        let threshold = UniswapV2ArbHook::minProfitThresholdCall::abi_decode_returns(result.result.output().unwrap()).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        Ok(threshold)
    }

    pub fn get_owner(
        evm: &mut impl Evm,
        contract_addr: Address,
    ) -> Result<Address, Box<dyn std::error::Error>> {
        let call = UniswapV2ArbHook::ownerCall {};
        let call_data = call.abi_encode();
        let result = evm.transact_system_call(Address::ZERO, contract_addr, call_data.into()).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

        let owner = UniswapV2ArbHook::ownerCall::abi_decode_returns(result.result.output().unwrap()).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        Ok(owner)
    }

    pub fn get_sequencer(
        evm: &mut impl Evm,
        contract_addr: Address,
    ) -> Result<Address, Box<dyn std::error::Error>> {
        let call = UniswapV2ArbHook::sequencerCall {};
        let call_data = call.abi_encode();
        let result = evm.transact_system_call(Address::ZERO, contract_addr, call_data.into()).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

        let sequencer = UniswapV2ArbHook::sequencerCall::abi_decode_returns(result.result.output().unwrap()).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        Ok(sequencer)
    }

    pub fn get_pair_registry(
        evm: &mut impl Evm,
        contract_addr: Address,
        pair_hash: B256,
    ) -> Result<Address, Box<dyn std::error::Error>> {
        let call = UniswapV2ArbHook::pairRegistryCall(pair_hash);
        let call_data = call.abi_encode();
        let result = evm.transact_system_call(Address::ZERO, contract_addr, call_data.into()).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

        let pair_address = UniswapV2ArbHook::pairRegistryCall::abi_decode_returns(result.result.output().unwrap()).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        Ok(pair_address)
    }

    pub fn get_pair_to_dex(
        evm: &mut impl Evm,
        contract_addr: Address,
        pair: Address,
    ) -> Result<Address, Box<dyn std::error::Error>> {
        let call = UniswapV2ArbHook::pairToDEXCall(pair);
        let call_data = call.abi_encode();
        let result = evm.transact_system_call(Address::ZERO, contract_addr, call_data.into()).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

        let dex_router = UniswapV2ArbHook::pairToDEXCall::abi_decode_returns(result.result.output().unwrap()).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        Ok(dex_router)
    }

    pub fn get_amount_out(
        evm: &mut impl Evm,
        contract_addr: Address,
        router: Address,
        token_in: Address,
        token_out: Address,
        amount_in: U256,
    ) -> Result<U256, Box<dyn std::error::Error>> {
        let call = UniswapV2ArbHook::_getAmountOutCall {
            router,
            tokenIn: token_in,
            tokenOut: token_out,
            amountIn: amount_in,
        };
        let call_data = call.abi_encode();
        let result = evm.transact_system_call(Address::ZERO, contract_addr, call_data.into()).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

        let amount_out = UniswapV2ArbHook::_getAmountOutCall::abi_decode_returns(result.result.output().unwrap()).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        Ok(amount_out)
    }
}

// Example usage:
//
// HooksPerpetualAuction Helper:
// let auction_contract = Address::from_str("0x292Fd8c1fCFE109089FB38a1528379A1Fe6Cae72").unwrap();
// let contract_addr = Address::from_str("0xd5Bf624C0c7192f13f5374070611D6f169bb5c88").unwrap();
// let topic0 = B256::from_str("0xd78ad95fa46c994b6551d0da85fc275fe613ce37657fb8d5e3d130840159d822").unwrap();
//
// Read functions:
// let hook = HooksPerpetualAuctionHelper::get_hook(&mut evm, auction_contract, contract_addr, topic0)?;
// let owner = HooksPerpetualAuctionHelper::get_owner(&mut evm, auction_contract)?;
// let gas_stipend = HooksPerpetualAuctionHelper::get_hook_gas_stipend(&mut evm, auction_contract)?;
//
// State-changing functions:
// let signer = Signer::try_from_secret(B256::from_str("0x..."))?; // Your private key
// let chain_id = 901; // OP Stack L2 chain ID
// let gas_limit = 1_000_000;
// let gas_price = 1_000_000_000; // 1 gwei
// let tx = HooksPerpetualAuctionHelper::execute_hook(
//     &mut db, auction_contract, contract_addr, topic0, topic1, topic2, topic3,
//     event_data, originator, signer, chain_id, gas_limit, gas_price
// )?;
//
// UniswapV2ArbHook Helper:
// let arb_contract = Address::from_str("0x29a79095352a718B3D7Fe84E1F14E9F34A35598e").unwrap();
//
// Read functions:
// let dex_count = UniswapV2ArbHookHelper::get_supported_dex_count(&mut evm, arb_contract)?;
// let min_profit = UniswapV2ArbHookHelper::get_min_profit_threshold(&mut evm, arb_contract)?;
// let max_trade_size = UniswapV2ArbHookHelper::get_max_trade_size(&mut evm, arb_contract)?;
//
// State-changing functions:
// let tx = UniswapV2ArbHookHelper::on_hook(
//     &mut db, arb_contract, contract_addr, topic0, topic1, topic2, topic3,
//     event_data, signer, chain_id, gas_limit, gas_price
// )?;