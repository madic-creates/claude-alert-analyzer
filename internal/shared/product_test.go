package shared

import "testing"

// TestProductConstants pins the exact string values of ProductK8s and
// ProductCheckMK. A mutation swapping the two constants would silently corrupt
// all Prometheus metrics (product ConstLabel) without this test.
func TestProductConstants(t *testing.T) {
	if got := ProductK8s.String(); got != "k8s" {
		t.Errorf("ProductK8s.String() = %q, want %q", got, "k8s")
	}
	if got := ProductCheckMK.String(); got != "checkmk" {
		t.Errorf("ProductCheckMK.String() = %q, want %q", got, "checkmk")
	}
}

// TestProductValid verifies the Valid() contract for known and unknown products.
func TestProductValid(t *testing.T) {
	tests := []struct {
		product Product
		want    bool
	}{
		{ProductK8s, true},
		{ProductCheckMK, true},
		{Product(""), false},
		{Product("unknown"), false},
	}
	for _, tt := range tests {
		if got := tt.product.Valid(); got != tt.want {
			t.Errorf("Product(%q).Valid() = %v, want %v", tt.product, got, tt.want)
		}
	}
}

// TestProductDistinct verifies the two constants have different string values.
// A swap mutation (ProductK8s="checkmk", ProductCheckMK="k8s") preserves
// validity but corrupts all metric labels and routing.
func TestProductDistinct(t *testing.T) {
	if ProductK8s == ProductCheckMK {
		t.Errorf("ProductK8s and ProductCheckMK must be distinct; both are %q", ProductK8s)
	}
}
