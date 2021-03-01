/* global artifacts:false, it:false, contract:false, assert:false */

const WyvernAtomicizer = artifacts.require('WyvernAtomicizer')
const WyvernExchange = artifacts.require('WyvernExchange')
const WyvernStatic = artifacts.require('WyvernStatic')
const WyvernRegistry = artifacts.require('WyvernRegistry')
const TestERC1155 = artifacts.require('TestERC1155')
const TestERC1271 = artifacts.require('TestERC1271')
const TestERC20 = artifacts.require('TestERC20')
const TestERC721 = artifacts.require('TestERC721')
const GlobalMaker = artifacts.require('GlobalMaker')

const Web3 = require('web3')
const provider = new Web3.providers.HttpProvider('http://localhost:8545')
const web3 = new Web3(provider)

const {wrap,hashOrder,ZERO_BYTES32,randomUint,NULL_SIG,assertIsRejected} = require('./aux')

const CHAIN_ID = 50

contract('WyvernExchange', (accounts) =>
	{
	let deploy_core_contracts = async () =>
		{
		let [registry,atomicizer] = await Promise.all([WyvernRegistry.new(), WyvernAtomicizer.new(), GlobalMaker.new()])
		let [exchange,statici] = await Promise.all([WyvernExchange.new(CHAIN_ID,[registry.address]),WyvernStatic.new(atomicizer.address)])
		await registry.grantInitialAuthentication(exchange.address)
		return {registry,exchange:wrap(exchange),atomicizer,statici}
		}

	let deploy = async contracts => Promise.all(contracts.map(contract => contract.new()))

	it('matches erc1155 nft-nft swap order',async () =>
		{
		let account_a = accounts[0]
		let account_b = accounts[6]
		
		let {exchange, registry, statici} = await deploy_core_contracts()
		let [erc1155, maker] = await deploy([TestERC1155, GlobalMaker])
		
		await registry.registerProxy({from: account_a})
		let proxy1 = await registry.proxies(account_a)
		assert.equal(true, proxy1.length > 0, 'no proxy address for account a')

		let proxy2 = await registry.proxies(maker.address)
		assert.equal(true, proxy2.length > 0, 'no proxy address for global maker')

    // what to do about approval from the maker contract
    // should be the user account approving
		
		await Promise.all([erc1155.setApprovalForAll(proxy1,true,{from: account_a}),erc1155.setApprovalForAll(proxy2,true,{from: account_b})])
		
		let nfts = [{tokenId:4,amount:1},{tokenId:5,amount:1}]
		await Promise.all([erc1155.mint(account_a,nfts[0].tokenId),erc1155.mint(account_b,nfts[1].tokenId)])
		
		const erc1155c = new web3.eth.Contract(erc1155.abi, erc1155.address)
		const selector = web3.eth.abi.encodeFunctionSignature('swapOneForOneERC1155(bytes,address[7],uint8[2],uint256[6],bytes,bytes)')
		
		const paramsOne = web3.eth.abi.encodeParameters(
			['address[2]', 'uint256[2]', 'uint256[2]'],
			[[erc1155.address, erc1155.address], [nfts[0].tokenId, nfts[1].tokenId], [nfts[0].amount, nfts[1].amount]]
			)

		const paramsTwo = web3.eth.abi.encodeParameters(
			['address[2]', 'uint256[2]', 'uint256[2]'],
			[[erc1155.address, erc1155.address], [nfts[1].tokenId, nfts[0].tokenId], [nfts[1].amount, nfts[0].amount]]
			)

		const one = {registry: registry.address, maker: account_a, staticTarget: statici.address, staticSelector: selector, staticExtradata: paramsOne, maximumFill: '1', listingTime: '0', expirationTime: '10000000000', salt: '7'}
		const two = {registry: registry.address, maker: account_b, staticTarget: statici.address, staticSelector: selector, staticExtradata: paramsTwo, maximumFill: '1', listingTime: '0', expirationTime: '10000000000', salt: '8'}

		const firstData = erc1155c.methods.safeTransferFrom(account_a, account_b, nfts[0].tokenId, nfts[0].amount, "0x").encodeABI() + ZERO_BYTES32.substr(2)
		const secondData = erc1155c.methods.safeTransferFrom(account_b, account_a, nfts[1].tokenId, nfts[1].amount, "0x").encodeABI() + ZERO_BYTES32.substr(2)
				
		const firstCall = {target: erc1155.address, howToCall: 0, data: firstData}
		const secondCall = {target: erc1155.address, howToCall: 0, data: secondData}
		const sigOne = NULL_SIG
		let sigTwo = await exchange.sign(two, account_b)

		await exchange.atomicMatch(one, sigOne, firstCall, two, sigTwo, secondCall, ZERO_BYTES32)
		let [new_balance1,new_balance2] = await Promise.all([erc1155.balanceOf(account_a, nfts[1].tokenId),erc1155.balanceOf(account_b, nfts[0].tokenId)])
		assert.isTrue(new_balance1.toNumber() > 0,'Incorrect owner')
		assert.isTrue(new_balance2.toNumber() > 0,'Incorrect owner')
		})
		
	})
