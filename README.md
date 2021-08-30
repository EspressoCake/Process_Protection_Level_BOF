# Process Protection Level Enumerator BOF
##
#### What is this?
- A Syscall-only BOF file intended to grab process protection attributes, limited to a handful that _Red Team_ operators and _pentesters_ would commonly be interested in.
##
#### What problem are you trying to solve?
- There are great tools that exist in order to stealthily obtain access to and dump `LSASS` memory, thanks to some wonderful authors.
    - These (to my knowledge) do not currently preempt an operator from unintentionally using the aforementioned to grab a valid `handle` to the `LSASS` process
    - Existing tooling (outside of references in blog posts from the always-helpful [@itm4n](https://twitter.com/itm4n)) does not currently enumerate the protection levels of a given process.  
        - Obtaining a handle to a [PPL](https://docs.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services-)-enabled process can lead to a _very_ dead `Beacon` in very short order
        - This aims to fill that void, allowing an operator to know exactly what a protection level of a desired process is (if any) before unintentionally shooting themselves in the foot and/or determine what their next step(s) would/should be, given the output
##
#### How do I build this?
```sh
git clone https://github.com/EspressoCake/Process_Protection_Level_BOF
cd Process_Protection_Level_BOF/src
make
```

#### How do I use this?
- Load the `Aggressor` `.cna` file from the `dist` directory, after building
- Determine whatever `PID` you wish to interrogate
- From a given `Beacon`:
    ```sh
    process_protection_enum PROCESS_ID_NUMBER
    ```
##
#### I tend to touch the stove carelessly, how are you taking care of the injury-prone?
- Currently, the `Aggressor` script has safeguards
    - The current `Beacon` is checked to ensure that it is administrative, and an `x64` process
##
#### What does the output look like?
##### Protected Process Output
![](https://i.ibb.co/7nF0G7v/image.png)
##### Unprotected Process Output
![](https://i.ibb.co/SRLVtMn/image.png)
