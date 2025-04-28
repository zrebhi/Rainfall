# Rainfall - Binary Exploitation

## Project Overview

Welcome to the Rainfall project! As a direct sequel to Snow Crash, this project delves deeper into the world of cybersecurity, focusing specifically on the exploitation of ELF-like binaries within an i386 system environment. Understanding how memory works, how programs execute, and how common programming practices can lead to vulnerabilities is key to both defending and analyzing software.

This project presents a series of challenges organized into levels (`level0` through `level9`, followed by `bonus0` through `bonus3`, culminating in the `end` user). Each level requires you to analyze a binary, discover its vulnerabilities, and exploit them to read the `.pass` file located in the home directory of the next level's user account. This password allows you to switch users and progress to the next challenge.

## Getting Started

- To participate in the challenges, you'll need to use the provided Rainfall virtual machine. You can download the ISO file here: [RainFall.iso](https://cdn.intra.42.fr/isos/RainFall.iso)
- Connect to the VM via SSH on port 4242 using the initial credentials `level0:level0`.

```bash
ssh level0@<VM_IP_ADDRESS> -p 4242
```
(The VM's IP address will be displayed upon boot or can be found using `ifconfig` after logging in locally).

## Challenge Themes

This project explores various binary exploitation concepts and techniques across its levels, including but not limited to:

*   Reverse Engineering ELF Binaries (using tools like GDB, Ghidra, objdump)
*   Stack-Based Buffer Overflows
*   Return Address Overwriting
*   Shellcode Injection and Execution
*   Format String Vulnerabilities
*   Integer Overflows
*   Exploiting `atoi` Behavior
*   Understanding Stack Protections (Canaries) and Bypasses (where applicable)
*   C++ Specific Vulnerabilities (e.g., Vtables, Class Structures - as seen in level9)
*   SUID Binary Exploitation Challenges

## Repository Purpose

This repository serves as a record of the solutions, code analysis, and resources used to complete each level of the Rainfall challenge, as required by the project guidelines ([`en.subject.pdf`](./en.subject.pdf)). Each level directory (`levelX`, `bonusX`) contains:
*   `source.c` or `source.cpp`: A human-readable representation of the exploited binary's source code.
*   `walkthrough.md`: A step-by-step explanation of the analysis, vulnerability, and exploitation process.
*   `walkthrough_fr.md`: French version of the walkthrough.
*   `flag`: Contains the password obtained for the *next* level's user.
*   `Ressources/` (optional): Contains any additional scripts, notes, or resources used for the level.

Have fun exploring the intricacies of binary exploitation!