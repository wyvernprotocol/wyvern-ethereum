/*

  << Exchange Core >>

*/

pragma solidity 0.5.1;

import "openzeppelin-solidity/contracts/ownership/Ownable.sol";

import "../lib/StaticCaller.sol";
import "../lib/ReentrancyGuarded.sol";
import "../lib/EIP712.sol";
import "../registry/ProxyRegistryInterface.sol";
import "../registry/AuthenticatedProxy.sol";

/**
 * @title ExchangeCore
 * @author Wyvern Protocol Developers
 */
contract ExchangeCore is ReentrancyGuarded, StaticCaller, EIP712 {

    /* Struct definitions. */

    /* A signature, convenience struct. */
    struct Sig {
        /* v parameter */
        uint8 v;
        /* r parameter */
        bytes32 r;
        /* s parameter */
        bytes32 s;
    }

    /* An order, convenience struct. */
    struct Order {
        /* Order maker address. */
        address maker;
        /* Order static target. */
        address staticTarget;
        /* Order static selector. */
        bytes4 staticSelector;
        /* Order static extradata. */
        bytes staticExtradata;
        /* Order maximum fill factor. */
        uint maximumFill;
        /* Order listing timestamp. */
        uint listingTime;
        /* Order expiration timestamp - 0 for no expiry. */
        uint expirationTime;
        /* Order salt to prevent duplicate hashes. */
        uint salt;
    }

    /* A call, convenience struct. */
    struct Call {
        /* Target */
        address target;
        /* How to call */
        AuthenticatedProxy.HowToCall howToCall;
        /* Calldata */
        bytes data;
    }

    /* Constants */

    /* Order typehash for EIP 712 compatibility. */
    bytes32 constant ORDER_TYPEHASH = keccak256(
        "Order(address maker,address staticTarget,bytes4 staticSelector,bytes staticExtradata,uint maximumFill,uint listingTime,uint expirationTime,uint salt)"
    );

    /* Variables */

    /* Trusted proxy registry contract. */
    ProxyRegistryInterface public registry;

    /* Order fill status, by maker address then by hash. */
    mapping(address => mapping(bytes32 => uint)) public fills;

    /* Orders verified by on-chain approval.
       Alternative to ECDSA signatures so that smart contracts can place orders directly.
       By maker address, then by hash. */
    mapping(address => mapping(bytes32 => bool)) public approved;

    /* Events */

    event OrderApproved     (bytes32 indexed hash, address indexed maker, address staticTarget, bytes4 staticSelector, bytes staticExtradata, uint maximumFill, uint listingTime, uint expirationTime, uint salt, bool orderbookInclusionDesired);
    event OrderFillChanged  (bytes32 indexed hash, address indexed maker, uint newFill);
    event OrdersMatched     (bytes32 firstHash, bytes32 secondHash, address indexed firstMaker, address indexed secondMaker, uint newFirstFill, uint newSecondFill, bytes32 indexed metadata);

    /* Functions */

    function hashOrder(Order memory order)
        internal
        pure
        returns (bytes32 hash)
    {
        /* Per EIP 712. */
        return keccak256(abi.encode(
            ORDER_TYPEHASH,
            order.maker,
            order.staticTarget,
            order.staticSelector,
            keccak256(order.staticExtradata),
            order.maximumFill,
            order.listingTime,
            order.expirationTime,
            order.salt
        ));
    }

    function hashToSign(bytes32 orderHash)
        internal
        view
        returns (bytes32 hash)
    {
        /* Calculate the string a user must sign. */
        return keccak256(abi.encodePacked(
            "\x19\x01",
            DOMAIN_SEPARATOR,
            orderHash
        ));
    }

    function exists(address what)
        internal
        view
        returns (bool)
    {
        uint size;
        assembly {
            size := extcodesize(what)
        }
        return size > 0;
    }

    function validateOrderParameters(Order memory order, bytes32 hash)
        internal
        view
        returns (bool)
    {
        /* Order must be listed and not be expired. */
        if (order.listingTime > block.timestamp || order.expirationTime <= block.timestamp) {
            return false;
        }

        /* Order must not have already been completely filled. */
        if (fills[order.maker][hash] >= order.maximumFill) {
            return false;
        }

        /* Order static target must exist. */
        if (!exists(order.staticTarget)) {
            return false;
        }

        return true;
    }

    function validateOrderAuthorization(bytes32 hash, address maker, Sig memory sig)
        internal
        view
        returns (bool)
    {
        /* Memoized authentication. If order has already been partially filled, order must be authenticated. */
        if (fills[maker][hash] > 0) {
            return true;
        }

        /* Order authentication. Order must be either: */

        /* (a): sent by maker */
        if (maker == msg.sender) {
            return true;
        }

        /* (b): previously approved */
        if (approved[maker][hash]) {
            return true;
        }
    
        /* (c): ECDSA-signed by maker. */
        if (ecrecover(hashToSign(hash), sig.v, sig.r, sig.s) == maker) {
            return true;
        }

        return false;
    }

    function encodeStaticCall(Order memory order, Call memory call, Order memory counterorder, Call memory countercall, address matcher, uint value, uint fill)
        internal
        pure
        returns (bytes memory)
    {
        /* This array wrapping is necessary to preserve static call target function stack space. */
        address[5] memory addresses = [order.maker, call.target, counterorder.maker, countercall.target, matcher];
        AuthenticatedProxy.HowToCall[2] memory howToCalls = [call.howToCall, countercall.howToCall];
        uint[6] memory uints = [value, order.maximumFill, order.listingTime, order.expirationTime, counterorder.listingTime, fill];
        return abi.encodeWithSelector(order.staticSelector, order.staticExtradata, addresses, howToCalls, uints, call.data, countercall.data);
    }

    function executeStaticCall(Order memory order, Call memory call, Order memory counterorder, Call memory countercall, address matcher, uint value, uint fill)
        internal
        view
        returns (uint)
    {
        return staticCallUint(order.staticTarget, encodeStaticCall(order, call, counterorder, countercall, matcher, value, fill));
    }

    function executeCall(address maker, Call memory call)
        internal
        returns (bool)
    {
        /* Assert target exists. */
        require(exists(call.target), "Call target does not exist");

        /* Retrieve delegate proxy contract. */
        OwnableDelegateProxy delegateProxy = registry.proxies(maker);

        /* Assert existence. */
        require(delegateProxy != OwnableDelegateProxy(0), "Delegate proxy does not exist for maker");

        /* Assert implementation. */
        require(delegateProxy.implementation() == registry.delegateProxyImplementation(), "Incorrect delegate proxy implementation for maker");
      
        /* Typecast. */
        AuthenticatedProxy proxy = AuthenticatedProxy(address(delegateProxy));
  
        /* Execute order. */
        return proxy.proxy(call.target, call.howToCall, call.data);
    }

    function approveOrderHash(bytes32 hash)
        internal
    {
        /* CHECKS */

        /* Assert order has not already been approved. */
        require(!approved[msg.sender][hash], "Order has already been approved");

        /* EFFECTS */

        /* Mark order as approved. */
        approved[msg.sender][hash] = true;
    }

    function approveOrder(Order memory order, bool orderbookInclusionDesired)
        internal
    {
        /* CHECKS */

        /* Assert sender is authorized to approve order. */
        require(order.maker == msg.sender, "Sender is not authorized to approve order");

        /* Calculate order hash. */
        bytes32 hash = hashOrder(order);

        /* Approve order hash. */
        approveOrderHash(hash);

        /* Log approval event. */
        emit OrderApproved(hash, order.maker, order.staticTarget, order.staticSelector, order.staticExtradata, order.maximumFill, order.listingTime, order.expirationTime, order.salt, orderbookInclusionDesired);
    }

    function setOrderFill(bytes32 hash, uint fill)
        internal
    {
        /* CHECKS */

        /* Assert fill is not already set. */
        require(fills[msg.sender][hash] != fill, "Fill is already set");

        /* EFFECTS */

        /* Mark order as accordingly filled. */
        fills[msg.sender][hash] = fill;

        /* Log order fill change event. */
        emit OrderFillChanged(hash, msg.sender, fill);
    }

    function atomicMatch(Order memory firstOrder, Sig memory firstSig, Call memory firstCall, Order memory secondOrder, Sig memory secondSig, Call memory secondCall, bytes32 metadata)
        internal
        reentrancyGuard
    {
        /* CHECKS */

        /* Calculate first order hash. */
        bytes32 firstHash = hashOrder(firstOrder);

        /* Check first order validity. */
        require(validateOrderParameters(firstOrder, firstHash), "First order has invalid parameters");

        /* Check first order authorization. */
        require(validateOrderAuthorization(firstHash, firstOrder.maker, firstSig), "First order failed authorization");

        /* Calculate second order hash. */
        bytes32 secondHash = hashOrder(secondOrder);

        /* Check second order validity. */
        require(validateOrderParameters(secondOrder, secondHash), "Second order has invalid parameters");

        /* Check second order authorization. */
        require(validateOrderAuthorization(secondHash, secondOrder.maker, secondSig), "Second order failed authorization");

        /* Prevent self-matching (possibly unnecessary, but safer). */
        require(firstHash != secondHash, "Self-matching orders is prohibited");

        /* INTERACTIONS */

        /* Transfer any msg.value.
           This is the first "asymmetric" part of order matching: if an order requires Ether, it must be the first order. */
        if (msg.value > 0) {
            address(uint160(firstOrder.maker)).transfer(msg.value);
        }

        /* Execute first call, assert success.
           This is the second "asymmetric" part of order matching: execution of the second order can depend on state changes in the first order, but not vice-versa. */
        assert(executeCall(firstOrder.maker, firstCall));

        /* Execute second call, assert success. */
        assert(executeCall(secondOrder.maker, secondCall));

        /* Static calls must happen after the effectful calls so that they can check the resulting state. */

        /* Fetch previous first order fill. */
        uint previousFirstFill = fills[firstOrder.maker][firstHash];

        /* Fetch previous second order fill. */
        uint previousSecondFill = fills[secondOrder.maker][secondHash];

        /* Execute first order static call, assert success, capture returned new fill. */
        uint firstFill = executeStaticCall(firstOrder, firstCall, secondOrder, secondCall, msg.sender, msg.value, previousFirstFill);

        /* Execute second order static call, assert success, capture returned new fill. */
        uint secondFill = executeStaticCall(secondOrder, secondCall, firstOrder, firstCall, msg.sender, uint(0), previousSecondFill);

        /* EFFECTS */

        /* Update first order fill, if necessary. */
        if (firstOrder.maker != msg.sender) {
            if (firstFill != previousFirstFill) {
                fills[firstOrder.maker][firstHash] = firstFill;
            }
        }

        /* Update second order fill, if necessary. */
        if (secondOrder.maker != msg.sender) {
            if (secondFill != previousSecondFill) {
                fills[secondOrder.maker][secondHash] = secondFill;
            }
        }

        /* LOGS */

        /* Log match event. */
        emit OrdersMatched(firstHash, secondHash, firstOrder.maker, secondOrder.maker, firstFill, secondFill, metadata);
    }

}
