// psudo code for packet reordering

ReorderPacket(pkt)
Input: pkt: new arrived TCP packet
desc <- SearchDescriptor(pkt);
if(desc != NULL){
	if(desc->nextseq == pkt->seq){
		Insert(pkt, desc);
		UpdateNextSeq(desc);
	} else if(desc->nextseq > pkt->seq){
		Drop(pkt);
	} else {
		Insert(pkt, desc);
	}
} else {
	panic();
}

UpdateNextSeq(desc)
Input: desc: the large receive offload descriptor
p = desc->packets_list.first;
desc->nextseq = p->seq + payload_len(p);
p = desc->packets_list.first->next;
while(p != NULL){
	if(p->seq == desc->nextseq){
		desc->nextseq += payload_len(p);
		p = p->next;
	} else {
		break;
	}
}
