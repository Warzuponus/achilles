package main

import (
	"sync"

	"github.com/Warzuponus/achilles/internal/inventory"
)

// A run asks what languages and dependencies the target has in up to six places
// (which scanners apply, fix verification, the review, the advisor, the threat
// model, research). Each was a full walk of the tree. The tree does not change
// during a run, so the answer is computed once per target and shared.
var inventoryCache struct {
	mu   sync.Mutex
	byID map[string]*inventoryResult
}

type inventoryResult struct {
	once sync.Once
	inv  inventory.Inventory
	err  error
}

// inventoryOf returns the target's inventory, walking the tree at most once per
// run however many callers ask.
func inventoryOf(target string) (inventory.Inventory, error) {
	inventoryCache.mu.Lock()
	if inventoryCache.byID == nil {
		inventoryCache.byID = map[string]*inventoryResult{}
	}
	r := inventoryCache.byID[target]
	if r == nil {
		r = &inventoryResult{}
		inventoryCache.byID[target] = r
	}
	inventoryCache.mu.Unlock()

	r.once.Do(func() { r.inv, r.err = inventory.Scan(target) })
	return r.inv, r.err
}

// resetInventory forgets cached inventories. run() calls it first, so a result
// never outlives the run it was computed for.
func resetInventory() {
	inventoryCache.mu.Lock()
	inventoryCache.byID = nil
	inventoryCache.mu.Unlock()
}
