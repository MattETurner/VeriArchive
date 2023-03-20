package main

import (
	"archive/zip"
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"flag"
	"fmt"
	"hash"
	"hash/fnv"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	dir := flag.String("dir", "", "Folder full path")
	output := flag.String("o", "", "Output archive file")
	hashAlgo := flag.String("hash", "", "Hashing algorithm (sha256, fnv1a, sha1, md5)")
	checksumFile := flag.String("checksum", "checksum.txt", "Checksum file name")
	verify := flag.Bool("verify", false, "Verify archive integrity (<dir> and <hash> are ignored))")

	flag.Parse()

	// Verify the integrity of the archive if the verify flag is set
	if *output != "" && *hashAlgo != "" && *verify {
		verifyChecksum(*output, *hashAlgo, *checksumFile)
		return
	}

	// Check if the required flags are set <dir>, <output> and <hash>
	if *dir == "" || *output == "" || *hashAlgo == "" {
		flag.Usage()
		return
	}

	hasher, err := getHasher(*hashAlgo)
	if err != nil {
		fmt.Println(err)
		return
	}
	// start the timer
	start := time.Now()

	go displayLoadingScreen()

	err = createZipArchive(*dir, *output, hasher)
	if err != nil {
		fmt.Println(err)
		return
	}
	// stop the timer
	elapsed := time.Since(start)
	//print the archive name
	fmt.Println("\nArchive name:", *output)
	//print the archive size
	archiveSize, err := getFileSize(*output)
	if err != nil {
		fmt.Println("Failed to get the archive size:", err)
		return
	}
	//print the archive size in a human readable format
	fmt.Println("Archive size:", humanReadableSize(archiveSize))

	err = checkFilesReadability(*output)
	if err != nil {
		fmt.Println("\nFailed to read the files in the archive:", err)
		return
	} else {
		fmt.Println("\nFiles in the archive are readable.")
	}
	fmt.Printf("Time start: %s\n", start.Format(time.RFC3339))
	fmt.Printf("Elapsed time: %s\n", elapsed)
	fmt.Println("Completed.")
	hashValue := hasher.Sum(nil)
	fmt.Printf("\033[33mHash (%s) : %x\033[0m\n", *hashAlgo, hashValue)
	writeChecksum(*hashAlgo, hashValue, *checksumFile)
	fmt.Println("Checksum file:", *checksumFile)
	// convert the hash value to a string
	hashValueString := fmt.Sprintf("%x", hashValue)
	//save a log file with the archive name, size, hash time start and elapsed time as a csv file
	saveLog(*output, humanReadableSize(archiveSize), *hashAlgo, hashValueString, start, elapsed)

}

func getHasher(hashAlgo string) (hash.Hash, error) {
	switch hashAlgo {
	case "sha256":
		return sha256.New(), nil
	case "fnv1a":
		return fnv.New64a(), nil
	case "sha1":
		return sha1.New(), nil
	case "md5":
		return md5.New(), nil
	default:
		return nil, fmt.Errorf("invalid hashing algorithm")
	}
}

func createZipArchive(dir, output string, hasher hash.Hash) error {
	zipFile, err := os.Create(output)
	if err != nil {
		return err
	}
	defer zipFile.Close()

	zipWriter := zip.NewWriter(zipFile)
	//defer zipWriter.Close()

	err = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		relPath, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}

		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}

		header.Name = relPath
		header.Method = zip.Deflate

		writer, err := zipWriter.CreateHeader(header)
		if err != nil {
			return err
		}

		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()

		_, err = io.Copy(writer, file)
		return err
	})

	if err != nil {
		return err
	}

	zipWriter.Close()

	_, err = zipFile.Seek(0, io.SeekStart)
	if err != nil {
		return err
	}
	_, err = io.Copy(hasher, zipFile)
	if err != nil {
		return err
	}
	return nil
}

func displayLoadingScreen() {
	for {
		fmt.Print(".")
		time.Sleep(1 * time.Second)
	}
}

func writeChecksum(hashAlgo string, hashValue []byte, checksumFile string) {
	file, err := os.Create(checksumFile)
	if err != nil {
		fmt.Printf("Error creating checksum file: %v\n", err)
		return
	}
	defer file.Close()
	// Write the checksum to the file using a compatible checksum format
	_, err = fmt.Fprintf(file, "%s %x", strings.ToUpper(hashAlgo), hashValue)
	if err != nil {
		fmt.Printf("Error writing checksum to file: %v\n", err)
		return
	}
}

func verifyChecksum(archive, hashAlgo, checksumFile string) {
	hasher, err := getHasher(hashAlgo)
	if err != nil {
		fmt.Println(err)
		return
	}

	file, err := os.Open(archive)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer file.Close()

	_, err = io.Copy(hasher, file)
	if err != nil {
		fmt.Println(err)
		return
	}

	hashValue := hasher.Sum(nil)
	fmt.Printf("\033[33mComputed Hash (%s): %x\033[0m", hashAlgo, hashValue)

	file, err = os.Open(checksumFile)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer file.Close()

	var checksumHash string
	var readHash []byte
	_, err = fmt.Fscanf(file, "%s %x", &checksumHash, &readHash)
	if err != nil {
		fmt.Println(err)
		return
	}

	if checksumHash != strings.ToUpper(hashAlgo) {
		fmt.Println(" \033[31mHashing algorithm mismatch\033[0m")
		return
	}

	if !bytes.Equal(hashValue, readHash) {
		fmt.Printf(" \033[31mHash mismatch: computed: %x, read: %x\033[0m\n", hashValue, readHash)
		return
	}

	fmt.Println(" \033[32mChecksum verified\033[0m")
}

func checkFilesReadability(archive string) error {
	zipReader, err := zip.OpenReader(archive)
	if err != nil {
		return err
	}
	defer zipReader.Close()

	for _, file := range zipReader.File {
		fileReader, err := file.Open()
		if err != nil {
			return fmt.Errorf("failed to open file %s: %v", file.Name, err)
		}
		defer fileReader.Close()

		_, err = io.Copy(io.Discard, fileReader)
		if err != nil {
			return fmt.Errorf("failed to read file %s: %v", file.Name, err)
		}
	}

	return nil
}

func getFileSize(filename string) (int64, error) {
	file, err := os.Open(filename)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return 0, err
	}

	return stat.Size(), nil
}

func humanReadableSize(size int64) string {
	units := []string{"B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"}
	i := 0
	for size >= 1024 && i < len(units)-1 {
		size /= 1024
		i++
	}
	return fmt.Sprintf("%d %s", size, units[i])
}

func saveLog(output string, archiveSize string, hashAlgo string, hashValue string, start time.Time, elapsed time.Duration) {
	logContent := fmt.Sprintf("Output: %s\nArchive Size: %s\nHash Algorithm: %s\nHash Value: %s\nStart Time: %s\nElapsed Time: %s\n",
		output, archiveSize, hashAlgo, hashValue, start.Format(time.RFC3339), elapsed)

	// Write the log to a file
	err := os.WriteFile("log.txt", []byte(logContent), 0644)

	if err != nil {
		fmt.Println("Error writing log file:", err)
		return
	}
	fmt.Println("Log saved to log.txt")
}
