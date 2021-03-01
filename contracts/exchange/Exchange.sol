/*

  << Exchange >>

*/

pragma solidity 0.7.5;

import "./ExchangeCore.sol";

/**
 * @title Exchange
 * @author Wyvern Protocol Developers
 */
contract Exchange is ExchangeCore {

    /* external ABI-encodable method wrappers. */

    function hashOrder_(address registry, address maker, address staticTarget, bytes4 staticSelector, bytes calldata staticExtradata, uint maximumFill, uint listingTime, uint expirationTime, uint salt)
        external
        pure
        returns (bytes32 hash)
    {
        return hashOrder(Order(registry, maker, staticTarget, staticSelector, staticExtradata, maximumFill, listingTime, expirationTime, salt));
    }

    function hashToSign_(bytes32 orderHash)
        external
        view
        returns (bytes32 hash)
    {
        return hashToSign(orderHash);
    }

    function validateOrderParameters_(address registry, address maker, address staticTarget, bytes4 staticSelector, bytes calldata staticExtradata, uint maximumFill, uint listingTime, uint expirationTime, uint salt)
        external
        view
        returns (bool)
    {
        Order memory order = Order(registry, maker, staticTarget, staticSelector, staticExtradata, maximumFill, listingTime, expirationTime, salt);
        return validateOrderParameters(order, hashOrder(order));
    }

    function approveOrderHash_(bytes32 hash)
        external
    {
        return approveOrderHash(hash);
    }

    function approveOrder_(address registry, address maker, address staticTarget, bytes4 staticSelector, bytes calldata staticExtradata, uint maximumFill, uint listingTime, uint expirationTime, uint salt, bool orderbookInclusionDesired)
        external
    {
        return approveOrder(Order(registry, maker, staticTarget, staticSelector, staticExtradata, maximumFill, listingTime, expirationTime, salt), orderbookInclusionDesired);
    }

    function setOrderFill_(bytes32 hash, uint fill)
        external
    {
        return setOrderFill(hash, fill);
    }

    function atomicMatch_(uint[16] memory uints, bytes4[2] memory staticSelectors,
        bytes memory firstExtradata, bytes memory firstCalldata, bytes memory secondExtradata, bytes memory secondCalldata,
        uint8[2] memory howToCalls, bytes32 metadata, bytes memory signatures)
        public
        payable
    {
        return atomicMatch(
            Order(address(uints[0]), address(uints[1]), address(uints[2]), staticSelectors[0], firstExtradata, uints[3], uints[4], uints[5], uints[6]),
            Call(address(uints[7]), AuthenticatedProxy.HowToCall(howToCalls[0]), firstCalldata),
            Order(address(uints[8]), address(uints[9]), address(uints[10]), staticSelectors[1], secondExtradata, uints[11], uints[12], uints[13], uints[14]),
            Call(address(uints[15]), AuthenticatedProxy.HowToCall(howToCalls[1]), secondCalldata),
            signatures,
            metadata
        );
    }

}
