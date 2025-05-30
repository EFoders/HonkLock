package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"honklock/cryptotools"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/atotto/clipboard"
	"golang.org/x/term"
)

const vaultsDir = "./vaults"

type VaultEntry struct {
	ID     string `json:"id"`
	Nonce  string `json:"nonce"`
	Cipher string `json:"cipher"`
}

type VaultFile struct {
	Salt    string       `json:"salt"`
	Entries []VaultEntry `json:"entries"`
}

func vaultPath(name string) string {
	if filepath.Dir(name) == "." {
		return filepath.Join(vaultsDir, name)
	}
	return name
}

func loadVault(name string) (VaultFile, error) {
	var vault VaultFile
	data, err := os.ReadFile(vaultPath(name))
	if err != nil {
		return vault, err
	}
	err = json.Unmarshal(data, &vault)
	return vault, err
}

func saveVault(name string, vault VaultFile) error {
	path := vaultPath(name)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(vault, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func promptInput(prompt string) string {
	fmt.Print(prompt)
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	return scanner.Text()
}

func promptPassword(prompt string) string {
	fmt.Print(prompt)
	password, _ := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	return string(password)
}

func ensureVaultsDir() error {
	if _, err := os.Stat(vaultsDir); os.IsNotExist(err) {
		err := os.MkdirAll(vaultsDir, 0700)
		if err != nil {
			return fmt.Errorf("failed to create vaults directory: %v", err)
		}
	}
	return nil
}

func printHelp() {
	fmt.Println("Available commands:")
	fmt.Println("  list               - List all vaults (if no vault selected) or entries in current vault")
	fmt.Println("  use <vaultfile>    - Select a vault to use")
	fmt.Println("  init <vaultfile>   - Initialize a new vault")
	fmt.Println("  add                - Add a new password entry to current vault")
	fmt.Println("  get                - Get password from current vault")
	fmt.Println("  rm                 - Remove an entry from current vault")
	fmt.Println("  update             - Update an entry in current vault")
	fmt.Println("  help               - Show this help message")
	fmt.Println("  back               - Deselect the current vault")
	fmt.Println("  exit, quit         - Exit the program")
}

func handleCommand(command string, vaultFile string, args []string) {
	switch command {
	case "add":
		if vaultFile == "" {
			fmt.Println("No vault selected.")
			return
		}
		vault, err := loadVault(vaultFile)
		if err != nil {
			fmt.Println("Failed to load vault:", err)
			return
		}
		password := promptPassword("Enter vault password (will be hidden): ")
		salt, _ := cryptotools.Base64Decode(vault.Salt)
		vaultKey := cryptotools.DeriveVaultKey([]byte(password), salt)

		var id string
		if len(args) >= 1 {
			id = args[0]
		} else {
			id = promptInput("Entry ID: ")
		}
		secret := promptPassword("Enter password for the entry (will be hidden): ")

		nonce, cipher, err := cryptotools.EncryptEntry([]byte(secret), vaultKey)
		if err != nil {
			fmt.Println("Encryption failed:", err)
			return
		}
		entry := VaultEntry{
			ID:     id,
			Nonce:  cryptotools.Base64Encode(nonce),
			Cipher: cryptotools.Base64Encode(cipher),
		}
		vault.Entries = append(vault.Entries, entry)
		err = saveVault(vaultFile, vault)
		if err != nil {
			fmt.Println("Failed to save vault:", err)
			return
		}
		fmt.Println("Entry added.")

	case "get":
		if vaultFile == "" {
			fmt.Println("No vault selected.")
			return
		}
		if len(args) < 1 {
			fmt.Println("Usage: get <entry_id>")
			return
		}
		entryID := args[0]

		vault, err := loadVault(vaultFile)
		if err != nil {
			fmt.Println("Failed to load vault:", err)
			return
		}
		password := promptPassword("Enter vault password (will be hidden): ")
		salt, _ := cryptotools.Base64Decode(vault.Salt)
		vaultKey := cryptotools.DeriveVaultKey([]byte(password), salt)

		for _, entry := range vault.Entries {
			if entry.ID == entryID {
				nonce, _ := cryptotools.Base64Decode(entry.Nonce)
				cipher, _ := cryptotools.Base64Decode(entry.Cipher)
				plaintext, err := cryptotools.DecryptEntry(cipher, nonce, vaultKey)
				if err != nil {
					fmt.Println("Decryption failed.")
					return
				}
				err = clipboard.WriteAll(string(plaintext))
				if err != nil {
					fmt.Println("Failed to copy to clipboard.")
					return
				}
				fmt.Println("Password copied to clipboard. It will be cleared in 10 seconds.")
				go func() {
					time.Sleep(10 * time.Second)
					clipboard.WriteAll("")
				}()
				time.Sleep(11 * time.Second)
				return
			}
		}
		fmt.Println("Entry not found.")

	case "rm":
		if vaultFile == "" {
			fmt.Println("No vault selected.")
			return
		}
		if len(args) < 1 {
			fmt.Println("Usage: rm <entry_id>")
			return
		}
		entryID := args[0]

		vault, err := loadVault(vaultFile)
		if err != nil {
			fmt.Println("Failed to load vault:", err)
			return
		}
		newEntries := []VaultEntry{}
		removed := false
		for _, entry := range vault.Entries {
			if entry.ID != entryID {
				newEntries = append(newEntries, entry)
			} else {
				removed = true
			}
		}
		if !removed {
			fmt.Println("Entry not found:", entryID)
			return
		}
		vault.Entries = newEntries
		err = saveVault(vaultFile, vault)
		if err != nil {
			fmt.Println("Failed to save vault:", err)
			return
		}
		fmt.Println("Entry removed:", entryID)

	case "update":
		if vaultFile == "" {
			fmt.Println("No vault selected.")
			return
		}
		if len(args) < 1 {
			fmt.Println("Usage: update <entry_id>")
			return
		}
		entryID := args[0]

		vault, err := loadVault(vaultFile)
		if err != nil {
			fmt.Println("Failed to load vault:", err)
			return
		}
		password := promptPassword("Enter vault password (will be hidden): ")
		salt, _ := cryptotools.Base64Decode(vault.Salt)
		vaultKey := cryptotools.DeriveVaultKey([]byte(password), salt)

		var found bool
		for i, entry := range vault.Entries {
			if entry.ID == entryID {
				newSecret := promptPassword("Enter new password for the entry (will be hidden): ")
				nonce, cipher, err := cryptotools.EncryptEntry([]byte(newSecret), vaultKey)
				if err != nil {
					fmt.Println("Encryption failed:", err)
					return
				}
				vault.Entries[i].Nonce = cryptotools.Base64Encode(nonce)
				vault.Entries[i].Cipher = cryptotools.Base64Encode(cipher)
				found = true
				break
			}
		}
		if !found {
			fmt.Println("Entry not found:", entryID)
			return
		}
		err = saveVault(vaultFile, vault)
		if err != nil {
			fmt.Println("Failed to save vault:", err)
			return
		}
		fmt.Println("Entry updated:", entryID)

	default:
		fmt.Println("Unknown command:", command)
	}
}

func main() {
	err := ensureVaultsDir()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	reader := bufio.NewReader(os.Stdin)
	currentVault := ""

	fmt.Println("\nWelcome to HonklockCLI, the lightweight password CLI password manager.\n Type 'help' for available commands.\n Written by E.Foden\n updated: 2025-05-30\n")

	for {
		if currentVault == "" {
			fmt.Print("honklock> ")
		} else {
			fmt.Printf("honklock [%s]> ", filepath.Base(currentVault))
		}
		input, _ := reader.ReadString('\n')
		args := strings.Fields(strings.TrimSpace(input))

		if len(args) == 0 {
			continue
		}

		cmd := strings.ToLower(args[0])

		switch cmd {
		case "back":
			if currentVault == "" {
				fmt.Println("No vault is currently selected.")
			} else {
				fmt.Println("Deselected vault:", currentVault)
				currentVault = ""
			}
		case "help":
			printHelp()
		case "exit", "quit":
			fmt.Println("Exiting honklock.")
			return
		case "list":
			if currentVault == "" {
				files, err := os.ReadDir(vaultsDir)
				if err != nil {
					fmt.Println("Failed to read vault directory:", err)
					break
				}
				fmt.Println("Available vaults:")
				for _, f := range files {
					if !f.IsDir() {
						fmt.Println(" -", f.Name())
					}
				}
			} else {
				vault, err := loadVault(currentVault)
				if err != nil {
					fmt.Println("Failed to load vault:", err)
					break
				}
				fmt.Println("Stored Entry IDs:")
				for _, e := range vault.Entries {
					fmt.Println(" -", e.ID)
				}
			}
		case "use":
			if len(args) < 2 {
				fmt.Println("Usage: use <vaultfile>")
				break
			}
			vp := vaultPath(args[1])
			if _, err := os.Stat(vp); os.IsNotExist(err) {
				fmt.Println("Vault does not exist:", args[1])
			} else {
				currentVault = args[1]
				fmt.Println("Using vault:", args[1])
			}
		case "init":
			if len(args) < 2 {
				fmt.Println("Usage: init <vaultfile>")
				break
			}
			vaultName := args[1]
			vaultPath := vaultName
			if !strings.Contains(vaultName, "/") {
				vaultPath = filepath.Join(vaultsDir, vaultName)
			}
			if _, err := os.Stat(vaultPath); err == nil {
				fmt.Println("Vault already exists:", vaultPath)
				break
			}

			password := promptPassword("Enter new vault password: ")
			confirm := promptPassword("Confirm vault password: ")
			if password != confirm {
				fmt.Println("Passwords do not match. Vault not created.")
				break
			}

			salt, _ := cryptotools.GenerateSalt()
			_ = cryptotools.DeriveVaultKey([]byte(password), salt)
			err := saveVault(vaultPath, VaultFile{Salt: cryptotools.Base64Encode(salt), Entries: []VaultEntry{}})
			if err != nil {
				fmt.Println("Error saving vault:", err)
				break
			}
			currentVault = vaultPath
			fmt.Println("Vault created and switched to:", currentVault)

		case "add", "get", "rm", "update":
			if currentVault == "" {
				fmt.Println("No vault selected. Use 'use <vaultfile>' first.")
			} else {
				handleCommand(cmd, currentVault, args[1:])

			}
		default:
			fmt.Println("Unknown command. Type 'help' for usage.")
		}
	}
}
