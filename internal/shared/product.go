package shared

// Product identifies which analyzer binary is emitting metrics. Used as a
// ConstLabel on the Prometheus registry.
type Product string

const (
	ProductK8s     Product = "k8s"
	ProductCheckMK Product = "checkmk"
)

// Valid reports whether p is one of the recognized products.
func (p Product) Valid() bool {
	return p == ProductK8s || p == ProductCheckMK
}

// String returns the lowercase string form used as the Prometheus label value.
func (p Product) String() string { return string(p) }
