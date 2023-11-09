package subtake

import (
	"fmt"
	"log"
	"sync"
)

type Options struct {
	Domains string
	Threads int
	Timeout int
	Output  string
	Ssl     bool
	All     bool
	Verbose bool
	Config  string
}

type Subdomain struct {
	Url string
}

/* Start processing from the defined options. */
func Process(o *Options) {
	urls := make(chan *Subdomain, o.Threads*2)
	resultsChan := make(chan Results, o.Threads*2) // Results channel
	fmt.Println("Starting process for: ")

	list, err := open(o.Domains)
	if err != nil {
		log.Fatalln(err)
	}

	wg := new(sync.WaitGroup)

	for i := 0; i < o.Threads; i++ {
		fmt.Println("Starting threads")
		wg.Add(1)
		go func() {
			for url := range urls {
				fmt.Printf("+ %s\n", url)

				result := url.dns(url) // Get the result
				resultsChan <- result  // Send result to channel
			}
			wg.Done()
		}()
	}

	for _, domain := range list {
		urls <- &Subdomain{Url: domain}
	}

	close(urls)
	wg.Wait()
	close(resultsChan) // Close results channel after all goroutines are done

	// Process results
	for result := range resultsChan {
		// Handle each result
		logVerboseNonVulnerable(result)
	}
}
