package auditlog

// 	Hello! This file is auto-generated.

type (

	// EventSet slice of Event
	//
	// This type is auto-generated.
	EventSet []*Event
)

// Walk iterates through every slice item and calls w(Event) err
//
// This function is auto-generated.
func (set EventSet) Walk(w func(*Event) error) (err error) {
	for i := range set {
		if err = w(set[i]); err != nil {
			return
		}
	}

	return
}

// Filter iterates through every slice item, calls f(Event) (bool, err) and return filtered slice
//
// This function is auto-generated.
func (set EventSet) Filter(f func(*Event) (bool, error)) (out EventSet, err error) {
	var ok bool
	out = EventSet{}
	for i := range set {
		if ok, err = f(set[i]); err != nil {
			return
		} else if ok {
			out = append(out, set[i])
		}
	}

	return
}
