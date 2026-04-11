// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "../src/SenseifiSubscriptionPayments.sol";

contract DeploySenseifiSubscriptionPayments is Script {
    function run() external returns (SenseifiSubscriptionPayments deployed) {
        uint256 deployerPk = vm.envUint("PRIVATE_KEY");
        address usdc = vm.envAddress("USDC_ADDRESS");
        address treasury = vm.envAddress("TREASURY_ADDRESS");
        address relayer = vm.envAddress("RELAYER_ADDRESS");

        vm.startBroadcast(deployerPk);
        deployed = new SenseifiSubscriptionPayments(usdc, treasury, relayer);
        vm.stopBroadcast();
    }
}
