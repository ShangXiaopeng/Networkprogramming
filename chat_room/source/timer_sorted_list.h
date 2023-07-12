#ifndef TIMER_SORTED_LIST_H_
#define TIMER_SORTED_LIST_H_


#include <time.h>
#include "client_data.h"

class sl_timer
{
public:
	time_t expire_time;
	void (*callback_func) (client_data*);
	client_data* user_data;
	sl_timer* prev;
	sl_timer* next;

public:
	sl_timer() : prev(NULL), next(NULL) {}
};

class timer_sorted_list
{
private:
	sl_timer* head;
	sl_timer* tail;
private:
	void insert_timer(sl_timer* ptmr, sl_timer* tsl_head)
	{
		sl_timer* prev = tsl_head;
		sl_timer* pcur = prev->next;

		while(pcur)
		{
			if(ptmr->expire_time < pcur->expire_time)
			{
				prev->next = ptmr;
				ptmr->next = pcur;
				pcur->prev = ptmr;
				ptmr->prev = prev;
				break;
			}
			prev = pcur;
			pcur = pcur->next;
		}

		if(!pcur)
		{
			prev->next = ptmr;
			ptmr->next = NULL;
			ptmr->prev = prev;
			tail = ptmr;
		}
	}

public:
	timer_sorted_list() : head(NULL), tail(NULL) {}

	~timer_sorted_list()
	{
		sl_timer* pcur = head;
		while(pcur)
		{
			head = pcur->next;
			pcur->user_data->timer = NULL;
			delete pcur;
			pcur = head;
		}
	}

	void insert_timer(sl_timer* ptmr)
	{
		if(!ptmr)
			return;
		if(!head)
		{
			head = ptmr;
			tail = ptmr;
			return;
		}
		if(ptmr->expire_time < head->expire_time)
		{
			ptmr->next = head;
			head->prev = ptmr;
			head = ptmr;
			return;
		}

		insert_timer(ptmr, head);
	}

	void update_timer(sl_timer* ptmr)
	{
		if(!ptmr)
			return;

		sl_timer* pcur = ptmr->next;
		if(!pcur || (ptmr->expire_time < pcur->expire_time))
			return;

		if(ptmr == head)
		{
			head = head->next;
			head->prev = NULL;
			ptmr->next = NULL;
			insert_timer(ptmr, head);
		}
		
		else
		{
			ptmr->prev->next = ptmr->next;
			ptmr->next->prev = ptmr->prev;
			insert_timer(ptmr, ptmr->next);
		}
	}

	void erase_timer(sl_timer* ptmr)
	{
		if(!ptmr)
			return;
		if((ptmr == head) && (ptmr == tail))
		{
			ptmr->user_data->timer = NULL; //
			delete ptmr;
			head = NULL;
			tail = NULL;
			return;
		}

		if(ptmr == head)
		{
			head = head->next;
			head->prev = NULL;
			ptmr->user_data->timer = NULL;
			delete ptmr;
			return;
		}

		if(ptmr == tail)
		{
			tail = tail->prev;
			tail->next = NULL;
			ptmr->user_data->timer = NULL;
			delete ptmr;
			return;
		}

		ptmr->prev->next = ptmr->next;
		ptmr->next->prev = ptmr->prev;
		ptmr->user_data->timer = NULL;
		delete ptmr;
	}

	void tick()
	{
		if(!head)
			return;
		printf("Timer tick once\n");


		time_t curr_time = time(NULL);
		sl_timer* pcur = head;

		while(pcur)
		{
			if(curr_time < pcur->expire_time)
				break;

			pcur->callback_func(pcur->user_data);
			pcur = pcur->next;
		}
	}
};


#endif

























