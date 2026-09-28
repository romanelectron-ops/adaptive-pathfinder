// node_isuserowned_test.go — N-7 (ТЗ APF v1.5, C8/O7): Node.IsUserOwned() — helper над уже
// существующими маркерами (Source=="manual" || IsChainPartner), без нового поля схемы.
package models

import "testing"

func TestNode_IsUserOwned_TruthTable(t *testing.T) {
	cases := []struct {
		name string
		node *Node
		want bool
	}{
		{"manual", &Node{Source: "manual"}, true},
		{"chain_partner_flag", &Node{IsChainPartner: true}, true},
		{"chain_partner_source_and_flag", &Node{Source: "chain_partner", IsChainPartner: true}, true},
		{"manual_and_chain", &Node{Source: "manual", IsChainPartner: true}, true},
		{"public_subscription", &Node{Source: "subscription"}, false},
		{"empty_source", &Node{Source: ""}, false},
		{"chain_partner_source_only_no_flag", &Node{Source: "chain_partner"}, false}, // без флага — только строка Source недостаточна
		{"nil_node", nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.node.IsUserOwned(); got != c.want {
				t.Fatalf("IsUserOwned() = %v, want %v (node=%+v)", got, c.want, c.node)
			}
		})
	}
}
