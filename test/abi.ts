export const abi = [
    {
        "type": "constructor",
        "inputs": [
            {
                "name": "authModule",
                "type": "address",
                "internalType": "address"
            },
            {
                "name": "tokenDeployer",
                "type": "address",
                "internalType": "address"
            }
        ],
        "stateMutability": "nonpayable"
    },
    {
        "type": "function",
        "name": "allTokensFrozen",
        "inputs": [],
        "outputs": [
            {
                "name": "",
                "type": "bool",
                "internalType": "bool"
            }
        ],
        "stateMutability": "pure"
    },
    {
        "type": "function",
        "name": "approveContractCall",
        "inputs": [
            {
                "name": "params",
                "type": "bytes",
                "internalType": "bytes"
            },
            {
                "name": "commandId",
                "type": "bytes32",
                "internalType": "bytes32"
            }
        ],
        "outputs": [],
        "stateMutability": "nonpayable"
    },
    {
        "type": "function",
        "name": "approveContractCallWithMint",
        "inputs": [
            {
                "name": "params",
                "type": "bytes",
                "internalType": "bytes"
            },
            {
                "name": "commandId",
                "type": "bytes32",
                "internalType": "bytes32"
            }
        ],
        "outputs": [],
        "stateMutability": "nonpayable"
    },
    {
        "type": "function",
        "name": "authModule",
        "inputs": [],
        "outputs": [
            {
                "name": "",
                "type": "address",
                "internalType": "address"
            }
        ],
        "stateMutability": "view"
    },
    {
        "type": "function",
        "name": "burnToken",
        "inputs": [
            {
                "name": "params",
                "type": "bytes",
                "internalType": "bytes"
            },
            {
                "name": "",
                "type": "bytes32",
                "internalType": "bytes32"
            }
        ],
        "outputs": [],
        "stateMutability": "nonpayable"
    },
    {
        "type": "function",
        "name": "callContract",
        "inputs": [
            {
                "name": "destinationChain",
                "type": "string",
                "internalType": "string"
            },
            {
                "name": "destinationContractAddress",
                "type": "string",
                "internalType": "string"
            },
            {
                "name": "payload",
                "type": "bytes",
                "internalType": "bytes"
            }
        ],
        "outputs": [],
        "stateMutability": "nonpayable"
    },
    {
        "type": "function",
        "name": "callContractWithToken",
        "inputs": [
            {
                "name": "destinationChain",
                "type": "string",
                "internalType": "string"
            },
            {
                "name": "destinationContractAddress",
                "type": "string",
                "internalType": "string"
            },
            {
                "name": "payload",
                "type": "bytes",
                "internalType": "bytes"
            },
            {
                "name": "symbol",
                "type": "string",
                "internalType": "string"
            },
            {
                "name": "amount",
                "type": "uint256",
                "internalType": "uint256"
            }
        ],
        "outputs": [],
        "stateMutability": "nonpayable"
    },
    {
        "type": "function",
        "name": "contractId",
        "inputs": [],
        "outputs": [
            {
                "name": "",
                "type": "bytes32",
                "internalType": "bytes32"
            }
        ],
        "stateMutability": "pure"
    },
    {
        "type": "function",
        "name": "deployToken",
        "inputs": [
            {
                "name": "params",
                "type": "bytes",
                "internalType": "bytes"
            },
            {
                "name": "",
                "type": "bytes32",
                "internalType": "bytes32"
            }
        ],
        "outputs": [],
        "stateMutability": "nonpayable"
    },
    {
        "type": "function",
        "name": "deployToken2",
        "inputs": [
            {
                "name": "params",
                "type": "bytes",
                "internalType": "bytes"
            },
            {
                "name": "",
                "type": "bytes32",
                "internalType": "bytes32"
            }
        ],
        "outputs": [],
        "stateMutability": "nonpayable"
    },
    {
        "type": "function",
        "name": "execute",
        "inputs": [
            {
                "name": "input",
                "type": "bytes",
                "internalType": "bytes"
            }
        ],
        "outputs": [],
        "stateMutability": "nonpayable"
    },
    {
        "type": "function",
        "name": "execute2",
        "inputs": [
            {
                "name": "input",
                "type": "bytes",
                "internalType": "bytes"
            }
        ],
        "outputs": [],
        "stateMutability": "nonpayable"
    },
    {
        "type": "function",
        "name": "getAddress",
        "inputs": [
            {
                "name": "key",
                "type": "bytes32",
                "internalType": "bytes32"
            }
        ],
        "outputs": [
            {
                "name": "",
                "type": "address",
                "internalType": "address"
            }
        ],
        "stateMutability": "view"
    },
    {
        "type": "function",
        "name": "getBool",
        "inputs": [
            {
                "name": "key",
                "type": "bytes32",
                "internalType": "bytes32"
            }
        ],
        "outputs": [
            {
                "name": "",
                "type": "bool",
                "internalType": "bool"
            }
        ],
        "stateMutability": "view"
    },
    {
        "type": "function",
        "name": "getBytes",
        "inputs": [
            {
                "name": "key",
                "type": "bytes32",
                "internalType": "bytes32"
            }
        ],
        "outputs": [
            {
                "name": "",
                "type": "bytes",
                "internalType": "bytes"
            }
        ],
        "stateMutability": "view"
    },
    {
        "type": "function",
        "name": "getInt",
        "inputs": [
            {
                "name": "key",
                "type": "bytes32",
                "internalType": "bytes32"
            }
        ],
        "outputs": [
            {
                "name": "",
                "type": "int256",
                "internalType": "int256"
            }
        ],
        "stateMutability": "view"
    },
    {
        "type": "function",
        "name": "getSession",
        "inputs": [
            {
                "name": "_custodianGroupId",
                "type": "bytes32",
                "internalType": "bytes32"
            }
        ],
        "outputs": [
            {
                "name": "",
                "type": "tuple",
                "internalType": "struct ScalarGateway.Session",
                "components": [
                    {
                        "name": "sequence",
                        "type": "uint64",
                        "internalType": "uint64"
                    },
                    {
                        "name": "phase",
                        "type": "uint8",
                        "internalType": "enum ScalarGateway.Phase"
                    }
                ]
            }
        ],
        "stateMutability": "view"
    },
    {
        "type": "function",
        "name": "getString",
        "inputs": [
            {
                "name": "key",
                "type": "bytes32",
                "internalType": "bytes32"
            }
        ],
        "outputs": [
            {
                "name": "",
                "type": "string",
                "internalType": "string"
            }
        ],
        "stateMutability": "view"
    },
    {
        "type": "function",
        "name": "getUint",
        "inputs": [
            {
                "name": "key",
                "type": "bytes32",
                "internalType": "bytes32"
            }
        ],
        "outputs": [
            {
                "name": "",
                "type": "uint256",
                "internalType": "uint256"
            }
        ],
        "stateMutability": "view"
    },
    {
        "type": "function",
        "name": "governance",
        "inputs": [],
        "outputs": [
            {
                "name": "",
                "type": "address",
                "internalType": "address"
            }
        ],
        "stateMutability": "view"
    },
    {
        "type": "function",
        "name": "implementation",
        "inputs": [],
        "outputs": [
            {
                "name": "",
                "type": "address",
                "internalType": "address"
            }
        ],
        "stateMutability": "view"
    },
    {
        "type": "function",
        "name": "isCommandExecuted",
        "inputs": [
            {
                "name": "commandId",
                "type": "bytes32",
                "internalType": "bytes32"
            }
        ],
        "outputs": [
            {
                "name": "",
                "type": "bool",
                "internalType": "bool"
            }
        ],
        "stateMutability": "view"
    },
    {
        "type": "function",
        "name": "isContractCallAndMintApproved",
        "inputs": [
            {
                "name": "commandId",
                "type": "bytes32",
                "internalType": "bytes32"
            },
            {
                "name": "sourceChain",
                "type": "string",
                "internalType": "string"
            },
            {
                "name": "sourceAddress",
                "type": "string",
                "internalType": "string"
            },
            {
                "name": "contractAddress",
                "type": "address",
                "internalType": "address"
            },
            {
                "name": "payloadHash",
                "type": "bytes32",
                "internalType": "bytes32"
            },
            {
                "name": "symbol",
                "type": "string",
                "internalType": "string"
            },
            {
                "name": "amount",
                "type": "uint256",
                "internalType": "uint256"
            }
        ],
        "outputs": [
            {
                "name": "",
                "type": "bool",
                "internalType": "bool"
            }
        ],
        "stateMutability": "view"
    },
    {
        "type": "function",
        "name": "isContractCallApproved",
        "inputs": [
            {
                "name": "commandId",
                "type": "bytes32",
                "internalType": "bytes32"
            },
            {
                "name": "sourceChain",
                "type": "string",
                "internalType": "string"
            },
            {
                "name": "sourceAddress",
                "type": "string",
                "internalType": "string"
            },
            {
                "name": "contractAddress",
                "type": "address",
                "internalType": "address"
            },
            {
                "name": "payloadHash",
                "type": "bytes32",
                "internalType": "bytes32"
            }
        ],
        "outputs": [
            {
                "name": "",
                "type": "bool",
                "internalType": "bool"
            }
        ],
        "stateMutability": "view"
    },
    {
        "type": "function",
        "name": "mintLimiter",
        "inputs": [],
        "outputs": [
            {
                "name": "",
                "type": "address",
                "internalType": "address"
            }
        ],
        "stateMutability": "view"
    },
    {
        "type": "function",
        "name": "mintToken",
        "inputs": [
            {
                "name": "params",
                "type": "bytes",
                "internalType": "bytes"
            },
            {
                "name": "",
                "type": "bytes32",
                "internalType": "bytes32"
            }
        ],
        "outputs": [],
        "stateMutability": "nonpayable"
    },
    {
        "type": "function",
        "name": "redeemToken",
        "inputs": [
            {
                "name": "params",
                "type": "bytes",
                "internalType": "bytes"
            },
            {
                "name": "",
                "type": "bytes32",
                "internalType": "bytes32"
            }
        ],
        "outputs": [],
        "stateMutability": "nonpayable"
    },
    {
        "type": "function",
        "name": "registerCustodianGroup",
        "inputs": [
            {
                "name": "params",
                "type": "bytes",
                "internalType": "bytes"
            },
            {
                "name": "",
                "type": "bytes32",
                "internalType": "bytes32"
            }
        ],
        "outputs": [],
        "stateMutability": "nonpayable"
    },
    {
        "type": "function",
        "name": "sendToken",
        "inputs": [
            {
                "name": "destinationChain",
                "type": "string",
                "internalType": "string"
            },
            {
                "name": "destinationAddress",
                "type": "string",
                "internalType": "string"
            },
            {
                "name": "symbol",
                "type": "string",
                "internalType": "string"
            },
            {
                "name": "amount",
                "type": "uint256",
                "internalType": "uint256"
            }
        ],
        "outputs": [],
        "stateMutability": "nonpayable"
    },
    {
        "type": "function",
        "name": "sessions",
        "inputs": [
            {
                "name": "",
                "type": "bytes32",
                "internalType": "bytes32"
            }
        ],
        "outputs": [
            {
                "name": "sequence",
                "type": "uint64",
                "internalType": "uint64"
            },
            {
                "name": "phase",
                "type": "uint8",
                "internalType": "enum ScalarGateway.Phase"
            }
        ],
        "stateMutability": "view"
    },
    {
        "type": "function",
        "name": "setTokenMintLimits",
        "inputs": [
            {
                "name": "symbols",
                "type": "string[]",
                "internalType": "string[]"
            },
            {
                "name": "limits",
                "type": "uint256[]",
                "internalType": "uint256[]"
            }
        ],
        "outputs": [],
        "stateMutability": "nonpayable"
    },
    {
        "type": "function",
        "name": "setup",
        "inputs": [
            {
                "name": "params",
                "type": "bytes",
                "internalType": "bytes"
            }
        ],
        "outputs": [],
        "stateMutability": "nonpayable"
    },
    {
        "type": "function",
        "name": "switchPhase",
        "inputs": [
            {
                "name": "params",
                "type": "bytes",
                "internalType": "bytes"
            },
            {
                "name": "",
                "type": "bytes32",
                "internalType": "bytes32"
            }
        ],
        "outputs": [],
        "stateMutability": "nonpayable"
    },
    {
        "type": "function",
        "name": "tokenAddresses",
        "inputs": [
            {
                "name": "symbol",
                "type": "string",
                "internalType": "string"
            }
        ],
        "outputs": [
            {
                "name": "",
                "type": "address",
                "internalType": "address"
            }
        ],
        "stateMutability": "view"
    },
    {
        "type": "function",
        "name": "tokenCustodianGroupIds",
        "inputs": [
            {
                "name": "",
                "type": "string",
                "internalType": "string"
            }
        ],
        "outputs": [
            {
                "name": "",
                "type": "bytes32",
                "internalType": "bytes32"
            }
        ],
        "stateMutability": "view"
    },
    {
        "type": "function",
        "name": "tokenDeployer",
        "inputs": [],
        "outputs": [
            {
                "name": "",
                "type": "address",
                "internalType": "address"
            }
        ],
        "stateMutability": "view"
    },
    {
        "type": "function",
        "name": "tokenFrozen",
        "inputs": [
            {
                "name": "",
                "type": "string",
                "internalType": "string"
            }
        ],
        "outputs": [
            {
                "name": "",
                "type": "bool",
                "internalType": "bool"
            }
        ],
        "stateMutability": "pure"
    },
    {
        "type": "function",
        "name": "tokenMintAmount",
        "inputs": [
            {
                "name": "symbol",
                "type": "string",
                "internalType": "string"
            }
        ],
        "outputs": [
            {
                "name": "",
                "type": "uint256",
                "internalType": "uint256"
            }
        ],
        "stateMutability": "view"
    },
    {
        "type": "function",
        "name": "tokenMintLimit",
        "inputs": [
            {
                "name": "symbol",
                "type": "string",
                "internalType": "string"
            }
        ],
        "outputs": [
            {
                "name": "",
                "type": "uint256",
                "internalType": "uint256"
            }
        ],
        "stateMutability": "view"
    },
    {
        "type": "function",
        "name": "transferGovernance",
        "inputs": [
            {
                "name": "newGovernance",
                "type": "address",
                "internalType": "address"
            }
        ],
        "outputs": [],
        "stateMutability": "nonpayable"
    },
    {
        "type": "function",
        "name": "transferMintLimiter",
        "inputs": [
            {
                "name": "newMintLimiter",
                "type": "address",
                "internalType": "address"
            }
        ],
        "outputs": [],
        "stateMutability": "nonpayable"
    },
    {
        "type": "function",
        "name": "transferOperatorship",
        "inputs": [
            {
                "name": "newOperatorsData",
                "type": "bytes",
                "internalType": "bytes"
            },
            {
                "name": "",
                "type": "bytes32",
                "internalType": "bytes32"
            }
        ],
        "outputs": [],
        "stateMutability": "nonpayable"
    },
    {
        "type": "function",
        "name": "upgrade",
        "inputs": [
            {
                "name": "newImplementation",
                "type": "address",
                "internalType": "address"
            },
            {
                "name": "newImplementationCodeHash",
                "type": "bytes32",
                "internalType": "bytes32"
            },
            {
                "name": "setupParams",
                "type": "bytes",
                "internalType": "bytes"
            }
        ],
        "outputs": [],
        "stateMutability": "nonpayable"
    },
    {
        "type": "function",
        "name": "validateContractCall",
        "inputs": [
            {
                "name": "commandId",
                "type": "bytes32",
                "internalType": "bytes32"
            },
            {
                "name": "sourceChain",
                "type": "string",
                "internalType": "string"
            },
            {
                "name": "sourceAddress",
                "type": "string",
                "internalType": "string"
            },
            {
                "name": "payloadHash",
                "type": "bytes32",
                "internalType": "bytes32"
            }
        ],
        "outputs": [
            {
                "name": "valid",
                "type": "bool",
                "internalType": "bool"
            }
        ],
        "stateMutability": "nonpayable"
    },
    {
        "type": "function",
        "name": "validateContractCallAndMint",
        "inputs": [
            {
                "name": "commandId",
                "type": "bytes32",
                "internalType": "bytes32"
            },
            {
                "name": "sourceChain",
                "type": "string",
                "internalType": "string"
            },
            {
                "name": "sourceAddress",
                "type": "string",
                "internalType": "string"
            },
            {
                "name": "payloadHash",
                "type": "bytes32",
                "internalType": "bytes32"
            },
            {
                "name": "symbol",
                "type": "string",
                "internalType": "string"
            },
            {
                "name": "amount",
                "type": "uint256",
                "internalType": "uint256"
            }
        ],
        "outputs": [
            {
                "name": "valid",
                "type": "bool",
                "internalType": "bool"
            }
        ],
        "stateMutability": "nonpayable"
    },
    {
        "type": "event",
        "name": "ContractCall",
        "inputs": [
            {
                "name": "sender",
                "type": "address",
                "indexed": true,
                "internalType": "address"
            },
            {
                "name": "destinationChain",
                "type": "string",
                "indexed": false,
                "internalType": "string"
            },
            {
                "name": "destinationContractAddress",
                "type": "string",
                "indexed": false,
                "internalType": "string"
            },
            {
                "name": "payloadHash",
                "type": "bytes32",
                "indexed": true,
                "internalType": "bytes32"
            },
            {
                "name": "payload",
                "type": "bytes",
                "indexed": false,
                "internalType": "bytes"
            }
        ],
        "anonymous": false
    },
    {
        "type": "event",
        "name": "ContractCallApproved",
        "inputs": [
            {
                "name": "commandId",
                "type": "bytes32",
                "indexed": true,
                "internalType": "bytes32"
            },
            {
                "name": "sourceChain",
                "type": "string",
                "indexed": false,
                "internalType": "string"
            },
            {
                "name": "sourceAddress",
                "type": "string",
                "indexed": false,
                "internalType": "string"
            },
            {
                "name": "contractAddress",
                "type": "address",
                "indexed": true,
                "internalType": "address"
            },
            {
                "name": "payloadHash",
                "type": "bytes32",
                "indexed": true,
                "internalType": "bytes32"
            },
            {
                "name": "sourceTxHash",
                "type": "bytes32",
                "indexed": false,
                "internalType": "bytes32"
            },
            {
                "name": "sourceEventIndex",
                "type": "uint256",
                "indexed": false,
                "internalType": "uint256"
            }
        ],
        "anonymous": false
    },
    {
        "type": "event",
        "name": "ContractCallApprovedWithMint",
        "inputs": [
            {
                "name": "commandId",
                "type": "bytes32",
                "indexed": true,
                "internalType": "bytes32"
            },
            {
                "name": "sourceChain",
                "type": "string",
                "indexed": false,
                "internalType": "string"
            },
            {
                "name": "sourceAddress",
                "type": "string",
                "indexed": false,
                "internalType": "string"
            },
            {
                "name": "contractAddress",
                "type": "address",
                "indexed": true,
                "internalType": "address"
            },
            {
                "name": "payloadHash",
                "type": "bytes32",
                "indexed": true,
                "internalType": "bytes32"
            },
            {
                "name": "symbol",
                "type": "string",
                "indexed": false,
                "internalType": "string"
            },
            {
                "name": "amount",
                "type": "uint256",
                "indexed": false,
                "internalType": "uint256"
            },
            {
                "name": "sourceTxHash",
                "type": "bytes32",
                "indexed": false,
                "internalType": "bytes32"
            },
            {
                "name": "sourceEventIndex",
                "type": "uint256",
                "indexed": false,
                "internalType": "uint256"
            }
        ],
        "anonymous": false
    },
    {
        "type": "event",
        "name": "ContractCallExecuted",
        "inputs": [
            {
                "name": "commandId",
                "type": "bytes32",
                "indexed": true,
                "internalType": "bytes32"
            }
        ],
        "anonymous": false
    },
    {
        "type": "event",
        "name": "ContractCallWithToken",
        "inputs": [
            {
                "name": "sender",
                "type": "address",
                "indexed": true,
                "internalType": "address"
            },
            {
                "name": "destinationChain",
                "type": "string",
                "indexed": false,
                "internalType": "string"
            },
            {
                "name": "destinationContractAddress",
                "type": "string",
                "indexed": false,
                "internalType": "string"
            },
            {
                "name": "payloadHash",
                "type": "bytes32",
                "indexed": true,
                "internalType": "bytes32"
            },
            {
                "name": "payload",
                "type": "bytes",
                "indexed": false,
                "internalType": "bytes"
            },
            {
                "name": "symbol",
                "type": "string",
                "indexed": false,
                "internalType": "string"
            },
            {
                "name": "amount",
                "type": "uint256",
                "indexed": false,
                "internalType": "uint256"
            }
        ],
        "anonymous": false
    },
    {
        "type": "event",
        "name": "Executed",
        "inputs": [
            {
                "name": "commandId",
                "type": "bytes32",
                "indexed": true,
                "internalType": "bytes32"
            }
        ],
        "anonymous": false
    },
    {
        "type": "event",
        "name": "GovernanceTransferred",
        "inputs": [
            {
                "name": "previousGovernance",
                "type": "address",
                "indexed": true,
                "internalType": "address"
            },
            {
                "name": "newGovernance",
                "type": "address",
                "indexed": true,
                "internalType": "address"
            }
        ],
        "anonymous": false
    },
    {
        "type": "event",
        "name": "MintLimiterTransferred",
        "inputs": [
            {
                "name": "previousGovernance",
                "type": "address",
                "indexed": true,
                "internalType": "address"
            },
            {
                "name": "newGovernance",
                "type": "address",
                "indexed": true,
                "internalType": "address"
            }
        ],
        "anonymous": false
    },
    {
        "type": "event",
        "name": "OperatorshipTransferred",
        "inputs": [
            {
                "name": "newOperatorsData",
                "type": "bytes",
                "indexed": false,
                "internalType": "bytes"
            }
        ],
        "anonymous": false
    },
    {
        "type": "event",
        "name": "RegisterCustodianGroup",
        "inputs": [
            {
                "name": "custodianGroupId",
                "type": "bytes32",
                "indexed": true,
                "internalType": "bytes32"
            },
            {
                "name": "sequence",
                "type": "uint64",
                "indexed": false,
                "internalType": "uint64"
            },
            {
                "name": "phase",
                "type": "uint8",
                "indexed": false,
                "internalType": "enum ScalarGateway.Phase"
            }
        ],
        "anonymous": false
    },
    {
        "type": "event",
        "name": "SwitchPhase",
        "inputs": [
            {
                "name": "custodianGroupId",
                "type": "bytes32",
                "indexed": true,
                "internalType": "bytes32"
            },
            {
                "name": "sequence",
                "type": "uint64",
                "indexed": true,
                "internalType": "uint64"
            },
            {
                "name": "from",
                "type": "uint8",
                "indexed": false,
                "internalType": "enum ScalarGateway.Phase"
            },
            {
                "name": "to",
                "type": "uint8",
                "indexed": false,
                "internalType": "enum ScalarGateway.Phase"
            }
        ],
        "anonymous": false
    },
    {
        "type": "event",
        "name": "TokenDeployed",
        "inputs": [
            {
                "name": "symbol",
                "type": "string",
                "indexed": false,
                "internalType": "string"
            },
            {
                "name": "tokenAddresses",
                "type": "address",
                "indexed": false,
                "internalType": "address"
            }
        ],
        "anonymous": false
    },
    {
        "type": "event",
        "name": "TokenMintLimitUpdated",
        "inputs": [
            {
                "name": "symbol",
                "type": "string",
                "indexed": false,
                "internalType": "string"
            },
            {
                "name": "limit",
                "type": "uint256",
                "indexed": false,
                "internalType": "uint256"
            }
        ],
        "anonymous": false
    },
    {
        "type": "event",
        "name": "TokenSent",
        "inputs": [
            {
                "name": "sender",
                "type": "address",
                "indexed": true,
                "internalType": "address"
            },
            {
                "name": "destinationChain",
                "type": "string",
                "indexed": false,
                "internalType": "string"
            },
            {
                "name": "destinationAddress",
                "type": "string",
                "indexed": false,
                "internalType": "string"
            },
            {
                "name": "symbol",
                "type": "string",
                "indexed": false,
                "internalType": "string"
            },
            {
                "name": "amount",
                "type": "uint256",
                "indexed": false,
                "internalType": "uint256"
            }
        ],
        "anonymous": false
    },
    {
        "type": "event",
        "name": "Upgraded",
        "inputs": [
            {
                "name": "implementation",
                "type": "address",
                "indexed": true,
                "internalType": "address"
            }
        ],
        "anonymous": false
    },
    {
        "type": "error",
        "name": "BurnFailed",
        "inputs": [
            {
                "name": "symbol",
                "type": "string",
                "internalType": "string"
            }
        ]
    },
    {
        "type": "error",
        "name": "ExceedMintLimit",
        "inputs": [
            {
                "name": "symbol",
                "type": "string",
                "internalType": "string"
            }
        ]
    },
    {
        "type": "error",
        "name": "InvalidAmount",
        "inputs": []
    },
    {
        "type": "error",
        "name": "InvalidAuthModule",
        "inputs": []
    },
    {
        "type": "error",
        "name": "InvalidChainId",
        "inputs": []
    },
    {
        "type": "error",
        "name": "InvalidCodeHash",
        "inputs": []
    },
    {
        "type": "error",
        "name": "InvalidCommands",
        "inputs": []
    },
    {
        "type": "error",
        "name": "InvalidGovernance",
        "inputs": []
    },
    {
        "type": "error",
        "name": "InvalidImplementation",
        "inputs": []
    },
    {
        "type": "error",
        "name": "InvalidMintLimiter",
        "inputs": []
    },
    {
        "type": "error",
        "name": "InvalidPhase",
        "inputs": []
    },
    {
        "type": "error",
        "name": "InvalidSetMintLimitsParams",
        "inputs": []
    },
    {
        "type": "error",
        "name": "InvalidTokenDeployer",
        "inputs": []
    },
    {
        "type": "error",
        "name": "MintFailed",
        "inputs": [
            {
                "name": "symbol",
                "type": "string",
                "internalType": "string"
            }
        ]
    },
    {
        "type": "error",
        "name": "NotGovernance",
        "inputs": []
    },
    {
        "type": "error",
        "name": "NotInitializedSession",
        "inputs": []
    },
    {
        "type": "error",
        "name": "NotMintLimiter",
        "inputs": []
    },
    {
        "type": "error",
        "name": "NotProxy",
        "inputs": []
    },
    {
        "type": "error",
        "name": "NotSelf",
        "inputs": []
    },
    {
        "type": "error",
        "name": "PhaseAlreadyExists",
        "inputs": []
    },
    {
        "type": "error",
        "name": "PhaseNotChanged",
        "inputs": []
    },
    {
        "type": "error",
        "name": "SetupFailed",
        "inputs": []
    },
    {
        "type": "error",
        "name": "TokenAlreadyExists",
        "inputs": [
            {
                "name": "symbol",
                "type": "string",
                "internalType": "string"
            }
        ]
    },
    {
        "type": "error",
        "name": "TokenContractDoesNotExist",
        "inputs": [
            {
                "name": "token",
                "type": "address",
                "internalType": "address"
            }
        ]
    },
    {
        "type": "error",
        "name": "TokenDeployFailed",
        "inputs": [
            {
                "name": "symbol",
                "type": "string",
                "internalType": "string"
            }
        ]
    },
    {
        "type": "error",
        "name": "TokenDoesNotExist",
        "inputs": [
            {
                "name": "symbol",
                "type": "string",
                "internalType": "string"
            }
        ]
    },
    {
        "type": "error",
        "name": "TokenTransferFailed",
        "inputs": []
    }
] as const;