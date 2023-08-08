
#ifndef APP__CONTROLLERS__INDEX_H
#define APP__CONTROLLERS__INDEX_H

#include <gwhfp/gwhfp.h>

namespace app {
namespace controllers {

class Index: public gwhfp::Controller {
public:
	using gwhfp::Controller::Controller;
	int index(struct gwhfp_req *req);
};

} /* namespace controllers */
} /* namespace app */

#endif /* APP__CONTROLLERS__INDEX_H */
