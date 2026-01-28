go test -bench=. | awk '
/ns\/op/ {
  ns = $(NF-1)
  ms = ns / 1000000
  printf "%-35s %10s ns/op    ≈ %.3f ms/op\n", $1, ns, ms
  next
}
{ print }
'
